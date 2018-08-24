package core.data;

import java.util.Objects;

import javax.json.JsonObject;

public class InternalDeviceData extends ADeviceData {

	public InternalDeviceData(String label) {
		super(label);
	}

	public void read(JsonObject data) {
		super.data = data;
		
		super.macs      = getPropertyArray("macs");
		super.throttled = Objects.equals(getProperty("throttle", "true"), "true");
		super.managed   = Objects.equals(getProperty("managed", "false"), "true");
		super.ports     = getPropertyArray("ports");
	}
}