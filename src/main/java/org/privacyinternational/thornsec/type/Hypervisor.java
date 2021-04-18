/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.type;

import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Direction;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidMachineModelException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.unit.pkg.InstalledUnit;
import org.privacyinternational.thornsec.profile.hypervisor.AHypervisorProfile;
import org.privacyinternational.thornsec.profile.hypervisor.Virtualbox;

import javax.json.stream.JsonParsingException;
import java.util.ArrayList;
import java.util.Collection;

/**
 * This is the representation of your HyperVisor itself.
 * 
 * These are things which should be done on a HyperVisor machine, regardless of
 * what hypervisor layer it's actually running
 */
public class Hypervisor extends AMachineType {

	private final AHypervisorProfile virtualbox;

	/**
	 * Create a new HyperVisor box, with initialised NICs, and initialise the
	 * virtualisation layer itself, including the building of Service machines
	 * 
	 * @throws JsonParsingException
	 * @throws ADataException
	 * @throws InvalidMachineModelException 
	 */
	public Hypervisor(ServerModel me) throws JsonParsingException, ADataException, InvalidMachineModelException {
		super(me);

		this.virtualbox = new Virtualbox(me);
	}

	@Override
	public Collection<IUnit> getInstalled() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.addAll(this.virtualbox.getInstalled());

		units.add(new InstalledUnit("whois", "proceed", "whois"));
		units.add(new InstalledUnit("tmux", "proceed", "tmux"));
		units.add(new InstalledUnit("socat", "proceed", "socat"));
		units.add(new InstalledUnit("metal_git", "proceed", "git"));
		return units;
	}

	@Override
	public Collection<IUnit> getPersistentConfig() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.addAll(this.virtualbox.getPersistentConfig());

		return units;
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.addAll(this.virtualbox.getPersistentFirewall());

		return units;
	}

	private String getNetworkBridge() {
		return getMachineModel().getNetworkInterfaces()
					.stream()
					.filter(nic -> Direction.LAN.equals(nic.getDirection()))
					.findAny()
					.get()
					.getIface();
	}

	@Override
	public Collection<IUnit> getLiveConfig() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();
		
		units.addAll(this.virtualbox.getLiveConfig());

		return units;
	}
}
