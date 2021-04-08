package org.privacyinternational.thornsec.core.model.machine;

import org.privacyinternational.thornsec.core.data.AData;
import org.privacyinternational.thornsec.core.data.machine.DeviceData;
import org.privacyinternational.thornsec.core.data.machine.ServerData;
import org.privacyinternational.thornsec.core.data.machine.ServiceData;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidTypeException;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;

public class ModelFactory {

    public static AMachineModel modelFromData(AData data, NetworkModel networkModel) throws AThornSecException {
        if (data instanceof DeviceData) {
            return new DeviceModel((DeviceData) data, networkModel);
        }
		else if (data instanceof ServiceData) {
            return new ServiceModel((ServiceData) data, networkModel);
        }
        else if (data instanceof ServerData) {
            return new ServerModel((ServerData) data, networkModel);
        }
		else {
            throw new InvalidTypeException("Unknown machine type for " + data.getLabel());
        }
    }
}