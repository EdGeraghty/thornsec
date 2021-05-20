/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data.network;

import org.privacyinternational.thornsec.core.data.AData;
import org.privacyinternational.thornsec.core.data.machine.AMachineData;
import org.privacyinternational.thornsec.core.data.machine.DeviceData;
import org.privacyinternational.thornsec.core.data.machine.ServerData;
import org.privacyinternational.thornsec.core.data.machine.ServiceData;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.InvalidJSONException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPropertyException;
import org.privacyinternational.thornsec.core.exception.data.NoValidUsersException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidMachineException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidUserException;

import javax.json.*;
import javax.json.stream.JsonParsingException;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * This class represents the state of our network *AS DEFINED IN THE JSON*
 *
 * This is our "interface" between the data and the models ThornSec will build.
 */
public class NetworkData extends AData {
	private String myUser;
	private String domain;

	private Set<AMachineData> machines;
	private Set<UserData> users;

	/**
	 * Create a new Network, reading in the data
	 * @param label the network's name
	 * @param data raw network data to read in
	 */
	public NetworkData(String label, Path filePath, JsonObject data) throws ADataException {
		super(label, filePath, data);
	}

	/**
	 * This is where we build the objects for our network.
	 * @return 
	 */
	@Override
	public NetworkData read(JsonObject networkJSONData) throws ADataException {
		readIncludes();
		readNetworkDomain();
		readNetworkConfigUser();
 		readUsers();
		readMachines();

		return this;
	}

	private Map<ServerData, Collection<ServiceData>> readHyperVisor(String label, JsonObject hypervisorData)
			throws ADataException {

		ServerData hv = new ServerData(label, getFilePath(), getData()); //read in defaults
		hv.read(hypervisorData); //Then hypervisor-related

		JsonObject servicesJsonObject = hypervisorData.getJsonObject("services");
		Collection<ServiceData> services = new ArrayList<>();

		for (final String serviceLabel : servicesJsonObject.keySet()) {
			ServiceData service = readService(serviceLabel, servicesJsonObject.getJsonObject(serviceLabel));

			service.setHypervisor(hv);
			service.setType("Service"); //Don't care if it's already set

			services.add(service);
		}

		Map<ServerData, Collection<ServiceData>> toReturn = new LinkedHashMap<>();

		toReturn.put(hv, services);

		return toReturn;
	}
	
	private ServiceData readService(String label, JsonObject serviceData) throws ADataException {
		ServiceData service = new ServiceData(label, getFilePath(), getData());
		service.read(serviceData);

		return service;
	}
	
	/**
	 * Read in a given server object, specialise and add it to our network.
	 * 
	 * If the object is a Hypervisor, interrogate it further for its nested
	 * services, read those in, and add those to the network too.
	 * 
	 * @param label The server's label
	 * @param serverDataObject raw JsonObject to read in
	 * @throws ADataException if attempting to add a machine with a duplicate label
	 */
	private void readServer(String label, JsonObject serverDataObject) throws ADataException {
		// We have to read it in first to find out what it is - we can then
		// replace it with a specialised version
		ServerData serverData = new ServerData(label, getFilePath(), getData()); //Read in network-level defaults
		serverData.read(serverDataObject); //Read in server-specific settings

		// If we've just hit a hypervisor machine, we need to dig a little,
		// because the services are nested inside
		// They *should* contain information about their services
		if (serverDataObject.containsKey("services")) {
			Map<ServerData, Collection<ServiceData>> hvAndServices = readHyperVisor(label, serverDataObject);
			for (Map.Entry<ServerData, Collection<ServiceData>> entry : hvAndServices.entrySet()) {
				ServerData hv = entry.getKey();
				Collection<ServiceData> services = entry.getValue();

				this.putMachine(hv);
				for (ServiceData service : services) {
					this.putMachine(service);
				}
			}
		}
		else {
			this.putMachine(serverData);
		}
	}

	private void readNetworkConfigUser() {
		if (!getData().containsKey("my_ssh_user")) {
			return;
		}

		this.myUser = getData().getJsonString("my_ssh_user").getString();
	}

	private void readMachines() throws ADataException {
		readServers();
		readDevices();
		readUserDevices();
	}

	private void readUserDevices() throws ADataException {
		if (!getData().containsKey("users")) {
			return;
		}

		final JsonObject jsonDevices = getData().getJsonObject("users");

		for (final String jsonDevice : jsonDevices.keySet()) {
			final DeviceData device = new DeviceData(jsonDevice);
			device.read(jsonDevices.getJsonObject(jsonDevice), getConfigFilePath());

			device.setType("User");

			if (device.getNetworkInterfaces().isPresent()) {
				putMachine(device);
			}
		}
	}

	private void readDevices() throws ADataException {
		if (!getData().containsKey("devices")) {
			return;
		}

		final JsonObject jsonDevices = getData().getJsonObject("devices");

		for (final String jsonDevice : jsonDevices.keySet()) {
			final DeviceData device = new DeviceData(jsonDevice);
			device.read(jsonDevices.getJsonObject(jsonDevice), getConfigFilePath());

			putMachine(device);
		}
	}

	private void readServers() throws ADataException {
		if (!getData().containsKey("servers")) {
			return;
		}

		final JsonObject jsonServers = getData().getJsonObject("servers");

		for (final String label : jsonServers.keySet()) {
			readServer(label, jsonServers.getJsonObject(label));
		}
	}

	/**
	 * Read in our Network-level domain from the JSON
	 */
	private void readNetworkDomain() {
		if (!getData().containsKey("domain")) {
			return;
		}

		this.domain = getData().getJsonString("domain").getString();
	}

	/**
	 * Parse and merge a given file with this. The include argument
	 * must be an absolute path to a JSON file, in your Operating System's
	 * native path style.
	 * 
	 * @throws InvalidPropertyException if a path is invalid
	 * @throws InvalidJSONException if the JSON itself is invalid
	 */
	private void readIncludes() throws InvalidPropertyException, InvalidJSONException {
		if (!getData().containsKey("includes")) {
			return;
		}

		for (JsonValue path : getData().getJsonArray("includes")) {
			readInclude(((JsonString) path).getString());
		}
	}

	/**
	 * Parse and merge a given file with this. The include argument
	 * must be an absolute path to a JSON file, in your Operating System's
	 * native path style.
	 * 
	 * @param includePath Absolute path to the JSON file to be read into our
	 * 		NetworkData
	 * @throws InvalidPropertyException if the path to the JSON is invalid
	 * @throws InvalidJSONException 
	 */
	private void readInclude(String includePath) throws InvalidPropertyException, InvalidJSONException {
		assert (null != getConfigFilePath().getParent());
		String configBase = getConfigFilePath().getParent().toString();
		Path includeFile = Path.of(configBase, includePath);

		try {
			String rawUTF8Data = Files.readString(includeFile);
			rawUTF8Data = rawUTF8Data.replaceAll("(?:/\\*(?:[^*]|(?:\\*+[^*/]))*\\*+/)|(?://.*)", "");

			JsonReader jsonReader = Json.createReader(new StringReader(rawUTF8Data));

			JsonObject currentData = getData();
			JsonObject includeData = jsonReader.readObject();

			JsonObjectBuilder newData = Json.createObjectBuilder();
			currentData.forEach(newData::add);
			includeData.forEach(newData::add);

			setData(newData.build());

			if (includeData.containsKey("includes")) {
				for (JsonValue path : includeData.getJsonArray("includes")) {
					this.readInclude(((JsonString) path).getString());
				}
			}
		}
		catch (IOException e) {
			throw new InvalidPropertyException("Invalid path to include:"
					+ includeFile.toString());
		}
		catch (JsonParsingException e) {
			throw new InvalidJSONException("Trying to read in " + includeFile.toString()
					+ " threw the following error " + e.getLocalizedMessage());
		}
	}

	/**
	 * Creates UserData objects from a given JSON network
	 * @throws InvalidUserException If there are duplicate users declared
	 * in this network's data
	 * @throws NoValidUsersException If there aren't any Users to 
	 */
	private void readUsers() throws InvalidUserException, NoValidUsersException {
		if (!getData().containsKey("users") || getData().getJsonObject("users").isEmpty()) {
			throw new NoValidUsersException("There must be at least one user on"
					+ " your network");
		}

		JsonObject jsonUsers = getData().getJsonObject("users");

		for (final String userLabel : jsonUsers.keySet()) {
			UserData user = new UserData(userLabel);
			user.read(jsonUsers.getJsonObject(userLabel));

			if (!this.users.add(user)) {
				throw new InvalidUserException("You have a duplicate user ("
						+ user.getLabel() + ") in your network");
			}
		}
	}

	/**
	 * Add (a) given machine(s) to your network. Machines must have unique labels
	 *  
	 * @param machinesData The machine to add to our network
	 * @throws InvalidMachineException on attempting to add a model with a
	 * 		duplicate label
	 */
	private void putMachine(AMachineData... machinesData) throws InvalidMachineException {
		for (AMachineData machineData : machinesData) {
			if (!this.machines.add(machineData)) {
				throw new InvalidMachineException("You have a duplicate machine ("
						+ machineData.getLabel() + ") in your network");
			}
		}
	}

	// Network only data
	public final String getUser() throws NoValidUsersException {
		if (this.myUser == null) {
			throw new NoValidUsersException();
		}

		return this.myUser;
	}

	/**
	 * @return the domain which applies to this network
	 */
	public final Optional<String> getDomain() {
		return Optional.ofNullable(this.domain);
	}

	/**
	 * Get all Machines on this network
	 * @return An
	 */
	public Set<AMachineData> getMachines() {
		return this.machines;
	}

	/**
	 * Gets all machines which have a given Type declared in their Data
	 * @param type The type of machines to get
	 * @return Optionally a specialised Set of machineDatas
	 */
	public Set<AMachineData> getMachines(Class<AMachineData> type) {
		return getMachines().stream()
				.filter(type::isInstance)
				.map(type::cast)
				.collect(Collectors.toSet());
	}

	public Set<UserData> getUsers() {
		return this.users;
	}
}
