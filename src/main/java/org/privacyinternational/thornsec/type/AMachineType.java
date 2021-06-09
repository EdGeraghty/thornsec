/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.type;

import inet.ipaddr.IPAddress;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.AMachineModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.NetworkInterfaceModel;
import org.privacyinternational.thornsec.core.profile.AStructuredProfile;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Any machine on a given network can only be of one Type, and that is represented here.
 *
 * A Type is designed to translate Core's Models into their functional counterparts.
 */
public abstract class AMachineType extends AStructuredProfile {
	
	public AMachineType(AMachineModel me) {
		super(me);
	}

	/**
	 * Which VLAN does this machine type belong to?
	 * @return a String representing the VLAN's name
	 */
	public abstract String getVLAN();

	/**
	 * What subnet should machines on this VLAN run on?
	 * @return an IPAddress representing the VLAN subnet
	 */
	public abstract IPAddress getVLANSubnet();

	/**
	 * Do the magic to turn our Models' NIC information into whatever is required by their Type
	 * @return a Collection of IUnits to build our NICs
	 */
	public Collection<IUnit> getNetworkInterfaceUnits() {
		final Collection<IUnit> units = new ArrayList<>();

		assert getMachineModel().getNetworkInterfaces() != null;
		for (NetworkInterfaceModel nic : getMachineModel().getNetworkInterfaces()) {
			nic.getNetworkFile().ifPresent(units::add);
			nic.getNetDevFile().ifPresent(units::add);
		}

		return units;
	}
}
