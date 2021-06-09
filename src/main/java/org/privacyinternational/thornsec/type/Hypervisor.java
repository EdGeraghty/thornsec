/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.type;

import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.unit.pkg.InstalledUnit;

import java.util.ArrayList;
import java.util.Collection;

/**
 * This is the representation of your HyperVisor itself.
 * 
 * These are things which should be done on a HyperVisor machine, regardless of
 * what hypervisor layer it's actually running
 */
public class Hypervisor extends Server {

	/**
	 * Create a new HyperVisor box, with initialised NICs, and initialise the
	 * virtualisation layer itself, including the building of Service machines
	 */
	public Hypervisor(ServerModel me) {
		super(me);
	}

	@Override
	public Collection<IUnit> getInstalled() {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new InstalledUnit("whois", "proceed", "whois"));
		units.add(new InstalledUnit("tmux", "proceed", "tmux"));
		units.add(new InstalledUnit("socat", "proceed", "socat"));
		units.add(new InstalledUnit("metal_git", "proceed", "git"));

		return units;
	}
}
