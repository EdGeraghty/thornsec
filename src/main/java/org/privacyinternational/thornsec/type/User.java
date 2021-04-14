/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.type;

import inet.ipaddr.HostName;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule;
import org.privacyinternational.thornsec.core.exception.data.InvalidPortException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.DeviceModel;

import java.util.Collection;
import java.util.LinkedHashSet;

/**
 * This is a User Device
 */
public class User extends AMachineType {

	public User(DeviceModel me) {
		super(me);
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws InvalidPortException {
		getMachineModel().addEgress(TrafficRule.Encapsulation.UDP, new HostName("*"));
		getMachineModel().addEgress(TrafficRule.Encapsulation.TCP, new HostName("*"));

		return new LinkedHashSet<>();
	}
}
