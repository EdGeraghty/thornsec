package org.privacyinternational.thornsec.core.data.machine.configuration;

import inet.ipaddr.HostName;
import org.privacyinternational.thornsec.core.exception.data.InvalidPortException;

import java.util.*;

public class TrafficRule {

	public enum Encapsulation {
		UDP, TCP
	}

	public enum Table {
		DNAT, FORWARD, INGRESS, EGRESS
	}

	private Encapsulation encapsulation;
	private Table table;
	private String source;
	private final Set<HostName> destinations;
	private final Set<Integer> ports;

	public TrafficRule(Encapsulation encapsulation, Table table, String source, Set<HostName> destinations, Set<Integer> ports) throws InvalidPortException {
		this.ports = new LinkedHashSet<>();
		this.destinations = new LinkedHashSet<>();

		this.encapsulation = encapsulation;
		this.setTable(table);
		this.setSource(source);
		this.addDestinations(destinations);
		this.addPorts(ports);
	}

	/**
	 * Deafult traffic rule to destination, on TCP port 443
	 * @param destination
	 * @throws InvalidPortException
	 */
	public TrafficRule(String source, HostName destination, Table table) throws InvalidPortException {
		this(Encapsulation.TCP, table, source, new HashSet<>(Collections.singletonList(destination)), new HashSet<>(Collections.singletonList(443)));
	}

	public TrafficRule() throws InvalidPortException {
		this(null, null, null, new LinkedHashSet<>(), new LinkedHashSet<>());
	}

	/**
	 * @return the encapsulation
	 */
	public Encapsulation getEncapsulation() {
		return this.encapsulation;
	}

	/**
	 * @param encapsulation the encapsulation to set
	 */
	public void setEncapsulation(Encapsulation encapsulation) {
		this.encapsulation = encapsulation;
	}

	public void addDestinations(Collection<HostName> collection) {
		this.destinations.addAll(collection);
	}

	public void addDestination(HostName destination) {
		this.destinations.add(destination);
	}

	/**
	 * @return the ports
	 */
	public Set<Integer> getPorts() {
		return this.ports;
	}

	/**
	 * @param ports the ports to set
	 * @throws InvalidPortException 
	 */
	public void addPorts(Integer... ports) throws InvalidPortException {
		if (ports == null) {
			return;
		}

		for (Integer port : ports) {
			if (((port < 0)) || ((port > 65535))) {
				throw new InvalidPortException(port);
			}

			this.ports.add(port);
		}
	}

	/**
	 * @param ports the ports to set
	 * @throws InvalidPortException 
	 */
	public void addPorts(Set<Integer> ports) throws InvalidPortException {
		addPorts(ports.toArray(Integer[]::new));
	}

	/**
	 * @return the destinations
	 */
	public Set<HostName> getDestinations() {
		return this.destinations;
	}

	public Table getTable() {
		return this.table;
	}

	public void setTable(Table table) {
		this.table = table;
	}

	public String getSource() {
		return source;
	}

	public void setSource(String source) {
		this.source = source;
	}


	public static class Builder {
		private TrafficRule trafficRule;

		public Builder() {
			try {
				trafficRule = new TrafficRule();

				trafficRule.setEncapsulation(TrafficRule.Encapsulation.TCP);
				trafficRule.addPorts(443);
			} catch (InvalidPortException e) {
				;; //In theory...
				e.printStackTrace();
			}
		}

		public Builder withEncapsulation(TrafficRule.Encapsulation encapsulation) {
			trafficRule.setEncapsulation(encapsulation);
			return this;
		}

		public Builder withDestinations(Collection<HostName> destinations) {
			trafficRule.addDestinations(destinations);
			return this;
		}

		public Builder withDestination(HostName destination) {
			trafficRule.addDestination(destination);
			return this;
		}

		public Builder withPort(int port) throws InvalidPortException {
			trafficRule.addPorts(port);
			return this;
		}

		public Builder withPorts(Integer... ports) throws InvalidPortException {
			trafficRule.addPorts(ports);
			return this;
		}

		public Builder withSource(String source) {
			trafficRule.setSource(source);
			return this;
		}

		public Builder withTable(TrafficRule.Table table) {
			trafficRule.setTable(table);
			return this;
		}

		public TrafficRule build() {
			return trafficRule;
		}
	}
}
