/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine;

import org.privacyinternational.thornsec.core.data.machine.ExternalDeviceData;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;

/**
 * This model represents an "External-Only" device on our network.
 *
 * An external-only device is one which can access the wider internet, but is
 * not allowed to access internal services.
 */
public class ExternalOnlyDeviceModel extends ADeviceModel {
	public ExternalOnlyDeviceModel(ExternalDeviceData myData, NetworkModel networkModel) throws AThornSecException {
		super(myData, networkModel);
	}

	@Override
	public void init() {}
}
