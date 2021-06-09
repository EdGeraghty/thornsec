/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.type;

import inet.ipaddr.IPAddress;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;

/**
 * This is a dedicated server on your network. This is something ThornSec needs
 * to know about, but shouldn't attempt to configure
 */
public class Dedicated extends Server {

	public Dedicated(ServerModel me)  {
		super(me);
	}

	@Override
	public String getVLAN() {
		return "Dedicated";
	}

	@Override
	public IPAddress getVLANSubnet() {
		return null;
	}
}
