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

	/**
	 * Initialise this model. This is where logic which relies on, for example,
	 * other models existing on our Network should live.
	 *
	 * @throws AThornSecException if something goes wrong.
	 */
	@Override
	public void init() throws AThornSecException {

	}
}
