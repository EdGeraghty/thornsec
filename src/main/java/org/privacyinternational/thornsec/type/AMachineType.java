package org.privacyinternational.thornsec.type;

import java.util.ArrayList;
import java.util.Collection;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.InvalidNetworkInterfaceException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.AMachineModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.NetworkInterfaceModel;
import org.privacyinternational.thornsec.core.profile.AStructuredProfile;

/**
 * This class represents configurations on a Machine on your network
 */
public class AMachineType extends AStructuredProfile {
	
	public AMachineType(AMachineModel me) {
		super(me);
	}

	@Override
	public Collection<IUnit> getUnits() throws AThornSecException {
		Collection<IUnit> units = new ArrayList<>(getNetworkInterfaceUnits());
		units.addAll(super.getUnits());
		return units;
	}

	/**
	 * Do the magic to turn our Models' NIC information into whatever is required by their Type
	 * @return a Collection of IUnits to build our NICs
	 * @throws InvalidNetworkInterfaceException if something goes wrong
	 */
	public Collection<IUnit> getNetworkInterfaceUnits() throws InvalidNetworkInterfaceException {
		final Collection<IUnit> units = new ArrayList<>();

		assert getMachineModel().getNetworkInterfaces() != null;
		for (NetworkInterfaceModel nic : getMachineModel().getNetworkInterfaces()) {
			nic.getNetworkFile().ifPresent(units::add);
			nic.getNetDevFile().ifPresent(units::add);
		}

		return units;
	}
}
