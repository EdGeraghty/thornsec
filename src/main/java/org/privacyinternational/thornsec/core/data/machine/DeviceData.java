/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data.machine;

import inet.ipaddr.MACAddressString;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData;
import org.privacyinternational.thornsec.core.exception.data.ADataException;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Abstract class for something representing "Device Data" on our network. This
 * is the parent class for all devices on our network. These are things like
 * users, or printers, or similar.
 */
public class DeviceData extends AMachineData {
	private Boolean managed;

	public DeviceData(String label, Path filePath, JsonObject data) throws ADataException {
		super(label, filePath, data);
	}

	@Override
	public DeviceData read(JsonObject data) throws ADataException {
		super.read(data);

		readIsManaged(data);
		readNICs(data);

		return this;
	}

	private final void readIsManaged(JsonObject data) {
		if (!data.containsKey("managed")) {
			return;
		}

		this.managed = data.getBoolean("managed");
	}

	private final void readNICs(JsonObject data) throws ADataException {
		if (!data.containsKey("macs")) {
			return;
		}

		final JsonArray macs = data.getJsonArray("macs");
		for (int i = 0; i < macs.size(); ++i) {
			final NetworkInterfaceData iface = new NetworkInterfaceData(getLabel(), getFilePath(), Json.createObjectBuilder().build());
			iface.setIface(getLabel() + i);
			iface.setMAC(new MACAddressString(macs.getString(i)).getAddress());
			putNetworkInterface(iface);
		}
	}

	public final Optional<Boolean> isManaged() {
		return Optional.ofNullable(this.managed);
	}
}
