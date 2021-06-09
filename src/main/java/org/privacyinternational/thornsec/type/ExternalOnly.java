/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.type;

import inet.ipaddr.AddressStringException;
import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
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

	@Override
	public String getVLAN() {
		return "ExternalOnlys";
	}

	@Override
	public IPAddress getVLANSubnet() {
		IPAddress subnet = null;
		try {
			subnet = new IPAddressString("172.28.0.0/16").toAddress();
		} catch (AddressStringException e) {
			;; //Famous last words...
			e.printStackTrace();
		}

		return subnet;
	}
}
