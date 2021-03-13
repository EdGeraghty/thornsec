/*
 * This code is part of the ThornSec project.
 * 
 * To learn more, please head to its GitHub repo: @privacyint
 * 
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data.machine;

import org.privacyinternational.thornsec.core.exception.data.ADataException;

import javax.json.JsonObject;
import java.nio.file.Path;

/**
 * Represents an external-only device on our network.
 * 
 * This is a device which is allowed wider connection to the
 * Internet, but shouldn't be allowed to see any of our internal infra
 */
public class UserDeviceData extends ADeviceData {
	public UserDeviceData(String label) {
		super(label);
	}

	@Override
	public UserDeviceData read(JsonObject data, Path configFilePath) throws ADataException {
		super.read(data, configFilePath);

		return this;
	}
}
