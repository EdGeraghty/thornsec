/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.type;

import inet.ipaddr.HostName;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.DeviceModel;

import java.util.Collection;
import java.util.HashSet;

/**
 * This is an external-only device on our network
 */
public class ExternalOnly extends Device {

	public ExternalOnly(DeviceModel me) {
		super(me);
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws AThornSecException {
		Collection<IUnit> units = new HashSet<>();

		units.addAll(super.getPersistentFirewall());

		getMachineModel().addEgress(TrafficRule.Encapsulation.UDP, new HostName("*"));
		getMachineModel().addEgress(TrafficRule.Encapsulation.TCP, new HostName("*"));

		return units;
	}
}
