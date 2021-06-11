/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine.configuration.networking;

import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Direction;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Inet;
import org.privacyinternational.thornsec.core.exception.data.InvalidIPAddressException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.InvalidNetworkInterfaceException;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;
import org.privacyinternational.thornsec.type.AMachineType;

/**
 * This model represents a MACVLAN. You have to stack this on top of a Trunk for
 * it to work, of course.
 */
public class MACVLANModel extends NetworkInterfaceModel {
	AMachineType type;

	public MACVLANModel(NetworkInterfaceData myData, NetworkModel networkModel) throws InvalidNetworkInterfaceException, InvalidIPAddressException {
		super(myData, networkModel);

		super.setInet(Inet.MACVLAN);
		super.setWeighting(20);
		super.setReqdForOnline(true);
		super.setConfigureWithoutCarrier(true);
		super.setGatewayOnLink(true);
		super.addToNetDev(Section.MACVLAN, "Mode", "bridge");
		super.setDirection(Direction.LAN);
	}

	public AMachineType getType() {
		return type;
	}

	public void setType(AMachineType type) {
		this.type = type;
	}
}
