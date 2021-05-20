/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data.network;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.stream.JsonParsingException;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IncompatibleAddressException;
import org.privacyinternational.thornsec.core.data.AData;
import org.privacyinternational.thornsec.core.data.machine.AMachineData;
import org.privacyinternational.thornsec.core.data.machine.DeviceData;
import org.privacyinternational.thornsec.core.data.machine.ServerData;
import org.privacyinternational.thornsec.core.data.machine.ServiceData;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.InvalidHostException;
import org.privacyinternational.thornsec.core.exception.data.InvalidIPAddressException;
import org.privacyinternational.thornsec.core.exception.data.InvalidJSONException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPropertyException;
import org.privacyinternational.thornsec.core.exception.data.NoValidUsersException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidMachineException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidUserException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidTypeException;

/**
 * This class represents the state of our network *AS DEFINED IN THE JSON*
 *
 * This is our "interface" between the data and the models ThornSec will build.
 */
public class NetworkData extends AData {
	private String myUser;
	private IPAddress configIP;
	private String domain;

	private Boolean adBlocking;
	private Boolean autoGenPassphrases;

	private Boolean vpnOnly;
	private Boolean autoGuest;

	private Set<HostName> upstreamDNS;

	private Map<String, IPAddress> subnets;

	private final Set<AMachineData> machines;
	private final Set<UserData> users;

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
		readUpstreamDNS();
		readNetworkDomain();
		readNetworkConfigIP();
		readNetworkConfigUser();
		readAdBlocking();
		readAutoGenPasswords();
		readVPNOnly();
		readAutoGuest();
		readSubnets();
		readUsers();
		readMachines();

		return this;
	}

	private ServerData readHyperVisor(String label, JsonObject hypervisorData)
			throws ADataException {

		ServerData hv = new ServerData(label);
		hv.read(getData(), getConfigFilePath());
		hv.read(hypervisorData, getConfigFilePath());

		JsonObject services = hypervisorData.getJsonObject("services");

		for (final String serviceLabel : services.keySet()) {
			ServiceData service = readService(serviceLabel, services.getJsonObject(serviceLabel));

			service.setHypervisor(hv);
			service.setType("Service");

			this.putMachine(service);
		}

		return hv;
	}
	
	private ServiceData readService(String label, JsonObject serviceData) throws ADataException {
		final ServiceData service = new ServiceData(label);
		service.read(getData(), getConfigFilePath());
		service.read(serviceData, getConfigFilePath());

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
		ServerData serverData = new ServerData(label);
		serverData.read(getData(), getConfigFilePath()); //Read in network-level defaults
		serverData.read(serverDataObject, getConfigFilePath()); //Read in server-specific settings

		// If we've just hit a hypervisor machine, we need to dig a little,
		// because the services are nested inside
		// They *should* contain information about their services
		if (serverDataObject.containsKey("services")) {
			serverData = readHyperVisor(label, serverDataObject);
		}

		this.putMachine(serverData);
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
	 * Read in any Subnet declarations made in the JSON
	 * @throws InvalidIPAddressException 
	 * @throws InvalidTypeException 
	 * @throws InvalidPropertyException 
	 */
	private void readSubnets() throws InvalidIPAddressException, InvalidPropertyException {
		if (!getData().containsKey("subnets")) {
			return;
		}

		final JsonObject jsonSubnets = getData().getJsonObject("subnets");

		for (final String label : jsonSubnets.keySet()) {
			String ip = (jsonSubnets.getJsonString(label)).getString();
			readSubnet(label, ip);
		}
	}
	
	private void readSubnet(String label, String ip) throws InvalidIPAddressException, InvalidPropertyException {
		if (null == this.subnets) {
			this.subnets = new HashMap<>();
		}

		try {
			this.subnets.put(label, new IPAddressString(ip).toAddress());
		} catch (AddressStringException | IncompatibleAddressException e) {
			throw new InvalidIPAddressException(ip + " is an invalid subnet");
		}
	}

	@Deprecated //TODO: This is a property of a Router
	private void readAutoGuest() {
		if (!getData().containsKey("guest_network")) {
			return;
		}

		this.autoGuest = getData().getBoolean("guest_network");
	}

	@Deprecated //TODO: This is a property of a Router
	private void readVPNOnly() {
		if (!getData().containsKey("vpn_only")) {
			return;
		}

		this.vpnOnly = getData().getBoolean("vpn_only");
	}

	/**
	 * Read in whether we should autogenerate secure passwords, or set the
	 * default from `NETWORK_AUTOGENPASSWDS`
	 */
	private void readAutoGenPasswords() {
		if (!getData().containsKey("autogen_passwds")) {
			return;
		}

		this.autoGenPassphrases = getData().getBoolean("autogen_passwds");
	}

	/**
	 * Read in whether or not we should be doing network-level ad-blocking.
	 */
	@Deprecated //TODO: this should be in Router(), not here.
	private void readAdBlocking() {
		if (!getData().containsKey("adblocking")) {
			return;
		}

		this.adBlocking = getData().getBoolean("adblocking");
	}

	/**
	 * Get the gateway IP address for our configuration
	 * @throws InvalidIPAddressException 
	 */
	private void readNetworkConfigIP() throws InvalidIPAddressException {
		if (!getData().containsKey("network_config_ip")) {
			return;
		}

		this.configIP = new IPAddressString(getData().getString("network_config_ip")
				.replaceAll("[^\\.0-9]", ""))
				.getAddress();

		if (this.configIP == null) {
			throw new InvalidIPAddressException(getData().getString("network_config_ip"));
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

	private void readUpstreamDNS() throws InvalidHostException {
		if (!getData().containsKey("upstream_dns")) {
			return;
		}

		this.upstreamDNS = getHostNameArray("upstream_dns");
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

	/**
	 * Get a given machine's data. You're not guaranteed that this machine is
	 * there, if you're reading from a config file 
	 *
	 * @param label the label of the Machine you wish to get
	 * @return the Machine's data
	 */
	public AMachineData getMachineData(String label) {
		return getMachines().stream()
				.filter(m -> m.getLabel().equalsIgnoreCase(label))
				.findFirst()
				.get();
	}
	
	// Network only data
	public final String getUser() throws NoValidUsersException {
		if (this.myUser == null) {
			throw new NoValidUsersException();
		}

		return this.myUser;
	}

	/**
	 * @return the upstream DNS server addresses
	 */
	public final Optional<Collection<HostName>> getUpstreamDNSServers() {
		return Optional.ofNullable(this.upstreamDNS);
	}

	/**
	 * Should we automatically build a guest network?
	 */
	public final Optional<Boolean> buildAutoGuest() {
		return Optional.ofNullable(this.autoGuest);
	}

	/**
	 * Should we autogenerate passphrases for users who haven't set a default?
	 */
	public final Boolean autoGenPassphrasess() {
		return this.autoGenPassphrases;
	}

	/**
	 * Gets the netmask - hardcoded as /30.
	 *
	 * @return the netmask (255.255.255.252)
	 */
	public final IPAddress getNetmask() {
		//TODO: THIS
		return new IPAddressString("255.255.255.252").getAddress();
	}

	/**
	 * This is either the IP of our router (if we're inside) or the public IP
	 * address (if it's an external resource)
	 */
	public final IPAddress getConfigIP() throws InvalidIPAddressException {
		if (this.configIP == null) {
			throw new InvalidIPAddressException("You must set a valid IP address for this network");
		}

		return this.configIP;
	}

	/**
	 * Should we do ad blocking at the router?
	 */
	public final Optional<Boolean> doAdBlocking() {
		return Optional.ofNullable(this.adBlocking);
	}

	/**
	 * Do we require users to be on a VPN connection to use our services?
	 * (This is only useful for internal services...)
	 */
	public final Optional<Boolean> isVPNOnly() {
		return Optional.ofNullable(this.vpnOnly);
	}

	/**
	 * @return the domain which applies to this network
	 */
	public final Optional<String> getDomain() {
		return Optional.ofNullable(this.domain);
	}

	public Optional<Map<String, IPAddress>> getSubnets() {
		return Optional.ofNullable(this.subnets);
	}

	public Optional<IPAddress> getSubnet(String subnet) {
		return Optional.ofNullable(this.subnets.get(subnet));
	}

	public Optional<String> getProperty(String label, String property) {
		return Optional.ofNullable(getMachineData(label).getData().getString(property, null));
	}

	public Optional<JsonObject> getProperties(String machine, String properties) {
		return Optional.ofNullable(getMachineData(machine).getData().getJsonObject(properties));
	}

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
