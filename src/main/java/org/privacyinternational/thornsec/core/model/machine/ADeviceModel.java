/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine;

import java.util.Collection;

import org.privacyinternational.thornsec.core.data.machine.ADeviceData;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPortException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;

/**
 * This model represents a device on our network.
 *
 * A device is something which is managed by ThornSec, but is not directly
 * configured. For instance, printers, or user machines.
 */
abstract public class ADeviceModel extends AMachineModel {
	private Boolean managed;

	public ADeviceModel(ADeviceData myData, NetworkModel networkModel)
			throws AThornSecException  {
		super(myData, networkModel);

		this.managed = myData.isManaged().orElse(false);
	}

	final public Boolean isManaged() {
		return this.managed;
	}

	final protected void setIsManaged(Boolean managed) {
		this.managed = managed;
	}

	final public Boolean hasRealNICs() {
		return getNetworkInterfaces()
				.stream()
				.anyMatch((nic) -> nic.getMac().isPresent());
	}
}
