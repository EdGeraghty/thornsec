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
import org.privacyinternational.thornsec.core.model.machine.ServerModel;

public abstract class Server extends AMachineType {
	public Server(ServerModel me) {
		super(me);
	}

	@Override
	public IPAddress getVLANSubnet() {
		IPAddress subnet = null;
			try {
			subnet = new IPAddressString("10.0.0.0/16").toAddress();
		} catch (
		AddressStringException e) {
			;; //Famous last words...
			e.printStackTrace();
		}

		return subnet;
	}

	@Override
	public String getVLAN() {
		return "Servers";
	}
}
