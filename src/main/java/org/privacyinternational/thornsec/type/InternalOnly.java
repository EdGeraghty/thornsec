/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.type;

import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import org.privacyinternational.thornsec.core.model.machine.DeviceModel;

/**
 * This is an internal-only device on our network
 */
public class InternalOnly extends Device {

	public InternalOnly(DeviceModel me) {
		super(me);
	}

	@Override
	public String getVLAN() {
		return "InternalOnlys";
	}

	@Override
	public IPAddress getVLANSubnet() {
		IPAddress subnet = null;
		try {
			subnet = new IPAddressString("172.24.0.0/16").toAddress();
		} catch (AddressStringException e) {
			;; //Famous last words...
			e.printStackTrace();
		}

		return subnet;
	}

}
