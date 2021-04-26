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
 * This is a device on our network
 */
public abstract class Device extends AMachineType {

	/**
	 * Device is never intended to be called directly
	 * @param me
	 */
	public Device(DeviceModel me) {
		super(me);
	}
}
