/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.dhcp;

import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.profile.AStructuredProfile;

import java.util.Map;

/**
 * This is a DHCP server of some type.
 *
 * DHCP servers are quite involved, so you'll need to implement everything!
 */
public abstract class ADHCPServerProfile extends AStructuredProfile {

	/**
	 * In your constructor, you will need
	 *
	 * @param me
	 */
	public ADHCPServerProfile(ServerModel me) {
		super(me);
	}


}
