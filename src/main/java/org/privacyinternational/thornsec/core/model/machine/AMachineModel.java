/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine;

import com.metapossum.utils.scanner.reflect.ClassesInPackageScanner;
import inet.ipaddr.*;
import inet.ipaddr.mac.MACAddress;
import org.privacyinternational.thornsec.core.StringUtils;
import org.privacyinternational.thornsec.core.data.machine.AMachineData;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Inet;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule.Encapsulation;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule.Table;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.InvalidIPAddressException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPortException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidProfileException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.AModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.DHCPClientInterfaceModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.NetworkInterfaceModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.StaticInterfaceModel;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;
import org.privacyinternational.thornsec.core.profile.AProfile;
import org.privacyinternational.thornsec.type.AMachineType;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import java.beans.Expression;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * This class represents a Machine on our network.
 * 
 * Everything on our network is a descendant from this class, 
 *
 * This is where we stash our various networking rules
 */
public abstract class AMachineModel extends AModel {
	private final Map<String, AProfile> profiles;
	private AMachineType type;

	private Collection<NetworkInterfaceModel> networkInterfaces;

	private final NetworkModel networkModel;

	private HostName domain;
	private Set<String> cnames;

	private InternetAddress emailAddress;

	private Boolean throttled;

	private Set<TrafficRule> firewallRules;

	AMachineModel(AMachineData myData, NetworkModel networkModel) throws AThornSecException {
		super(myData);

		this.networkModel = networkModel;

		setNICsFromData();
		setDomainFromData();
		setEmailFromData();
		setCNAMEsFromData();
		setFirewallFromData();

		this.profiles = new LinkedHashMap<>();
		setTypeFromData();
	}

	private void setTypeFromData() throws InvalidProfileException {
		String type = getData().getType();

		if (null == type || type.equals("")) {
			throw new InvalidProfileException("Must provide a type for " + getLabel());
		}

		this.type = reflectedType(type);
	}

	protected AProfile reflectedProfile(String profile) throws InvalidProfileException {
		Collection<Class<?>> classes;
		try {
			classes = new ClassesInPackageScanner()
					.setResourceNameFilter((packageName, fileName) ->
							fileName.equals(profile + ".class"))
					.scan("org.privacyinternational.thornsec.profile");

			return (AProfile) Class.forName(classes.iterator().next().getName())
					.getDeclaredConstructor(ServerModel.class)
					.newInstance(this);
		} catch (Exception e) {
			throw new InvalidProfileException(
				"Profile " + profile + " threw an exception..." +
					"\nMachine: " + getLabel() +
					"\nNetwork: " + getNetworkModel().getLabel() +
					"\n" +
					"\nException: " + e.getCause()
			);
		}
	}

	protected void addProfiles() throws InvalidProfileException {
		if (getData().getProfiles().isEmpty()) {
			return;
		}

		for (String profile : getData().getProfiles().get()) {
			addProfile(profile);
		}
	}

	private void addProfile(String profile) throws InvalidProfileException {
		this.profiles.put(profile, reflectedProfile(profile));
	}

	@Override
	public Collection<IUnit> getUnits() throws AThornSecException {
		Collection<IUnit> units = new ArrayList<>();

		units.addAll(getType().getUnits());

		for (AProfile profile : this.getProfiles().values()) {
			units.addAll(profile.getUnits());
		}

		return units;
	}

	public final NetworkModel getNetworkModel() {
		return networkModel;
	}

	private void setFirewallFromData() {
		this.firewallRules = getData().getTrafficRules();
	}

	public void addFirewallRule(TrafficRule rule) {
		this.firewallRules.add(rule);
	}

	private void setCNAMEsFromData() {
		this.cnames = getData().getCNAMEs().orElse(new LinkedHashSet<>());
	}

	private void setDomainFromData() {
		this.domain = getData().getDomain().orElse(new HostName("lan"));
	}

	/**
	 * Set up and initialise our various NICs as set from our Data
	 * @throws AThornSecException
	 */
	private void setNICsFromData() throws AThornSecException {
		if (getData().getNetworkInterfaces().isEmpty()) {
			return;
		}

		for (NetworkInterfaceData nicData : getData().getNetworkInterfaces().get().values()) {
			NetworkInterfaceModel nicModel = buildNICFromData(nicData);
			nicModel.init();
			this.addNetworkInterface(nicModel);
		}
	}

	private NetworkInterfaceModel buildNICFromData(NetworkInterfaceData ifaceData) throws AThornSecException {
		NetworkInterfaceModel nicModel = null;
		
		if (null == ifaceData.getInet()
				|| ifaceData.getInet().equals(Inet.STATIC)) {
			nicModel = new StaticInterfaceModel(ifaceData, getNetworkModel());
		}
		else {
			nicModel = new DHCPClientInterfaceModel(ifaceData, getNetworkModel());
		}

		return nicModel;
	}

	private void setEmailFromData() {
		try {
			this.emailAddress = getData().getEmailAddress()
					.orElse(new InternetAddress(getLabel() + "@" + getDomain()));
		} catch (AddressException e) {
			;; // You should not be able to get here. 
		}
	}

	public final void addNetworkInterface(NetworkInterfaceModel ifaceModel) {
		if (this.networkInterfaces == null) {
			this.networkInterfaces = new ArrayList<>();
		}

		this.networkInterfaces.add(ifaceModel);
	}

	public final Collection<NetworkInterfaceModel> getNetworkInterfaces() {
		return this.networkInterfaces;
	}

	/**
	 * Get all public IP addresses assigned to this machine
	 * @return an ArrayList of all public IP addresses
	 */
	public final Collection<IPAddress> getExternalIPs() {
		return getIPs()
					.stream()
					.filter(ip -> !ip.isLocal())
					.collect(Collectors.toCollection(ArrayList::new));
	}

	public final InternetAddress getEmailAddress() {
		return this.emailAddress;
	}

	public final Optional<Set<String>> getCNAMEs() {
		return Optional.ofNullable(this.cnames);
	}

	public HostName getDomain() {
		return this.domain;
	}

	public String getHostName() {
		return StringUtils.stringToAlphaNumeric(getLabel(), "-");
	}
	
	public final Boolean isThrottled() {
		return this.throttled;
	}

	/**
	 * Returns all IP addresses related to this machine
	 * @return
	 */
	public Collection<IPAddress> getIPs() {
		final Collection<IPAddress> ips = new ArrayList<>();

		getNetworkInterfaces().forEach(nic -> {
			nic.getAddresses().ifPresent(ips::addAll);
		});

		return ips;
	}

	public MACAddress generateMAC(String iface) {
		final String name = getLabel() + iface;

		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-512");
		} catch (final NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		md.update(name.getBytes());

		final byte[] byteData = md.digest();
		final StringBuilder hashCodeBuffer = new StringBuilder();
		for (final byte element : byteData) {
			hashCodeBuffer.append(Integer.toString((element & 0xff) + 0x100, 16).substring(1));

			if (hashCodeBuffer.length() == 6) {
				break;
			}
		}

		final String address = "080027" + hashCodeBuffer.toString();

		try {
			return new MACAddressString(address).toAddress();
		} catch (final AddressStringException | IncompatibleAddressException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

	public Set<TrafficRule> getFirewallRules() {
		return this.firewallRules;
	}

	/**
	 * Add a TCP egress (outbound/Internet) firewall rule to this machine
	 * @param destination a HostName representing the destination as either a
	 * 			hostname e.g. privacyinternational.org or IP address 
	 * @throws InvalidPortException if the port you're attempting to set is
	 * 			invalid
	 */
	public void addEgress(HostName destination) throws InvalidPortException {
		addEgress(Encapsulation.TCP, destination);
	}

	/**
	 * Add an egress (outbound/Internet) firewall rule to this machine
	 * @param encapsulation TCP/UDP
	 * @param destination a HostName representing the destination as either a
	 * 			hostname e.g. privacyinternational.org or IP address, optionally
	 * 			with a port (host:port) or defaults to 443
	 * @throws InvalidPortException if the port you're attempting to set is
	 * 			invalid
	 */
	public void addEgress(Encapsulation encapsulation, HostName destination) throws InvalidPortException {
		TrafficRule egressRule = new TrafficRule.Builder()
									.withTable(Table.EGRESS)
									.withDestination(destination)
									.withEncapsulation(encapsulation)
									.withSource(this.getHostName())
									.withPorts(destination.getPort())
									.build();

		this.addFirewallRule(egressRule);
	}

	/**
	 * Set this Machine to listen to TCP traffic on the provided port.
	 * 
	 * If the machine has been given (an) external IP(s), builds an ingress rule
	 * & allows access from LAN.
	 * 
	 * Don't use this method if you don't want these ports to be potentially
	 * publicly accessible.
	 * @param port port to listen on
	 * @throws InvalidPortException if trying to set an invalid port
	 */
	public void addListen(Integer port) throws InvalidPortException {
		addListen(Encapsulation.TCP, port);
	}

	/**
	 * Set this Machine to listen to {TCP|UDP} traffic *on all available interfaces*
	 * on the provided port(s).
	 * 
	 * If the machine has been given (an) external IP(s), builds an ingress rule
	 * & allows access from LAN.
	 * 
	 * Don't use this method if you don't want these ports to be potentially
	 * publicly accessible.
	 * 
	 * @param encapsulation TCP|UDP 
	 * @param ports port(s) to listen on
	 * @throws InvalidPortException if trying to listen on an invalid port
	 */
	public void addListen(Encapsulation encapsulation, Integer... ports) throws InvalidPortException {
		if (! this.getExternalIPs().isEmpty()) {
			try {
				addWANOnlyListen(encapsulation, ports);
			}
			catch (InvalidIPAddressException e) {
				;; //You shouldn't be able to get here.
				;; //Famous last words, right? :)
				e.printStackTrace();
			}
		}

		addLANOnlyListen(encapsulation, ports);
	}

	/**
	 * Set this Machine to listen to {TCP|UDP} traffic from our LAN machines on
	 * the provided port(s).
	 * 
	 * This method only exposes the port(s) to our LAN.
	 * @param encapsulation TCP|UDP
	 * @param ports port(s) to listen on
	 * @throws InvalidPortException if trying to listen on an invalid port
	 */
	public void addLANOnlyListen(Encapsulation encapsulation, Integer... ports) throws InvalidPortException {
		TrafficRule internalListenRule = new TrafficRule.Builder()
											.withTable(Table.FORWARD)
											.withEncapsulation(encapsulation)
											.withPorts(ports)
											.withDestination(new HostName(this.getHostName()))
											.withSource("*")
											.build();

		this.addFirewallRule(internalListenRule);
	}

	/**
	 * Set this Machine to listen to {TCP|UDP} traffic from The Internet on the
	 * provided port(s).
	 * 
	 * This method makes this machine publicly accessible on its external IP
	 * address.
	 * @param encapsulation TCP|UDP
	 * @param ports port(s) to listen on
	 * @throws InvalidIPAddressException if the machine doesn't have public IPs
	 * @throws InvalidPortException if trying to listen on an invalid port
	 */
	public void addWANOnlyListen(Encapsulation encapsulation, Integer... ports) throws InvalidIPAddressException, InvalidPortException {
		if (this.getExternalIPs().isEmpty()) {
			throw new InvalidIPAddressException("Trying to listen to WAN on "
					+ getLabel() + " but it has no pulicly accessible IP address.");
		}

		TrafficRule externalListenRule = new TrafficRule.Builder()
												.withTable(Table.INGRESS)
												.withEncapsulation(encapsulation)
												.withPorts(ports)
												.withDestination(new HostName(this.getHostName()))
												.withSource("*")
												.build();

		this.addFirewallRule(externalListenRule);
	}

	/**
	 * Redirect traffic from $originalDestination:$ports to $this:$ports.
	 * 
	 * This is done using Destination Network Address Translation, which replaces
	 * the $originalDestination IP address in each packet with $this
	 * @param encapsulation TCP|UDP
	 * @param originalDestination the original destination machine
	 * @param ports ports
	 * @throws InvalidPortException 
	 */
	public void addDNAT(Encapsulation encapsulation, AMachineModel originalDestination, Integer... ports) throws InvalidPortException {
		TrafficRule dnatRule = new TrafficRule.Builder()
									.withTable(Table.DNAT)
									.withEncapsulation(encapsulation)
									.withPorts(ports)
									.withSource(originalDestination.getHostName())
									.withDestination(new HostName(this.getHostName()))
									.build();

		this.addFirewallRule(dnatRule);
	}

	/**
	 * Redirect TCP traffic from $originalDestination:$ports to $this:$ports
	 * 
	 * This is done using Destination Network Address Translation, which replaces
	 * the $originalDestination IP address in each packet with $this
	 * @param originalDestination the original destination address
	 * @param ports ports
	 * @throws InvalidPortException 
	 */
	public void addDNAT(AMachineModel originalDestination, Integer... ports) throws InvalidPortException {
		addDNAT(Encapsulation.TCP, originalDestination, ports);
	}

	protected AMachineType reflectedType(String type) throws InvalidProfileException {
		Class<?> typeClass;
		try {
			typeClass = new ClassesInPackageScanner()
								.setResourceNameFilter((packageName, fileName) ->
									fileName.equals(type + ".class")
								)
								.scan("org.privacyinternational.thornsec.type")
								.iterator().next();

			return (AMachineType) new Expression(typeClass, "new", new Object[]{this}).getValue();
		} catch (Exception e) {
			throw new InvalidProfileException(
					"Type " + type + " threw an exception..." +
							"\nMachine: " + getLabel() +
							"\nNetwork: " + getNetworkModel().getLabel() +
							"\n" +
							"\nException: " + e.getMessage()
			);
		}
	}

	public Map<String, AProfile> getProfiles() {
		return this.profiles;
	}

	@Override
	public AMachineData getData() {
		return (AMachineData) super.getData();
	}

}
