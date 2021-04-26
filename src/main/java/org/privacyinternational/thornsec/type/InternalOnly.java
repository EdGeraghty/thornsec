/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.type;

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
		return "InternalOnly";
	}
}
