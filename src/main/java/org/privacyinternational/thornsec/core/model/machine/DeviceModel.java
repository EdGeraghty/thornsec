/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine;

import org.privacyinternational.thornsec.core.data.machine.DeviceData;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;

/**
 * This model represents a device on our network.
 *
 * A device is something which is managed by ThornSec, but is not directly
 * configured. For instance, printers, or user machines.
 */
  public class DeviceModel extends AMachineModel {
	private Boolean managed;

	public DeviceModel(DeviceData myData, NetworkModel networkModel)
			throws AThornSecException  {
		super(myData, networkModel);

		this.managed = getData().isManaged().orElse(false);
	}

	final public Boolean isManaged() {
		return this.managed;
	}

	@Override
	public DeviceData getData() {
		return (DeviceData) super.getData();
	}
}
