/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.type;

import org.privacyinternational.thornsec.core.model.machine.ServerModel;

/**
 * This is a Server, which represents a VM on a HyperVisor
 */
public class Server extends AMachine {

	public Server(ServerModel me) {
		super(me);
	}
}
