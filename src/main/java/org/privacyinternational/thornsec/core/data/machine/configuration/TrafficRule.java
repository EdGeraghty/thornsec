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
	private Set<HostName> destinations;
	private Set<Integer> ports;

	public TrafficRule() {

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

	public void addDestinations(Collection<HostName> destinations) {
		destinations.forEach(
				destination -> this.addDestination(destination)
		);
	}

	public void addDestination(HostName destination) {
		if (null == this.destinations) {
			this.destinations = new HashSet<>();
		}

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
		if (null == ports) {
			return;
		}

		if (null == this.ports) {
			this.ports = new HashSet<>();
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

	/**
	 * TrafficRule is a perfect place to use a Builder Design Pattern
	 */
	public static class Builder {
		private final TrafficRule trafficRule;

		public Builder() {
			trafficRule = new TrafficRule();

			trafficRule.setEncapsulation(TrafficRule.Encapsulation.TCP); //Default to TCP
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
