/*
 * This code is part of the ThornSec project.
 * 
 * To learn more, please head to its GitHub repo: @privacyint
 * 
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.stream.JsonParsingException;

import inet.ipaddr.HostName;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.InvalidHostException;

/**
 * Abstract class for something representing "Data" on our network.
 * 
 * This is something which has been read() from a JSON, and for our purposes
 * acts as a DAO.
 */
public abstract class AData {

	private final String label;
	private JsonObject data;
	private Path configFilePath;

	/**
	 * Instantiates a new data object.
	 *
	 * @param label the label for this object
	 */
	public AData(String label) {
		this.label = label;
		this.data = null;
		this.configFilePath = null;
	}

	/**
	 * JSON read method - must be overridden by descendants
	 *
	 * @param data the JSON data
	 * @param configFilePath path to the config file the data came from
	 * @return 
	 * @throws ADataException
	 */
	public AData read(JsonObject data, Path configFilePath) throws ADataException {
		this.configFilePath = configFilePath;
		this.data = data;

		return this;
	}

	/**
	 * Gets the object label.
	 *
	 * @return the object label
	 */
	public final String getLabel() {
		return this.label;
	}

	/**
	 * Gets the path to the config file this AData was initially read() against
	 *
	 * @return the path, or null if not reading from a file
	 */
	public final Path getConfigFilePath() {
		return this.configFilePath;
	}

	/**
	 * Gets the object's data.
	 *
	 * @return the data
	 */
	public final JsonObject getData() {
		return this.data;
	}

	/**
	 * Set the object's data
	 *
	 * @param data
	 */
	public final void setData(JsonObject data) {
		this.data = data;
	}

	/**
	 *
	 * @param key
	 * @return true if key is present in the data, false otherwise (including if data is null)
	 */
	public boolean keyIsPresent(String key) {
		return (null != getData() && getData().containsKey(key));
	}

	public Set<HostName> getHostNameArray(String key) throws InvalidHostException {
		if (!keyIsPresent(key)) {
			return null;
		}

		Set<HostName> hosts = new HashSet<>();
		final JsonArray jsonHosts = getData().getJsonArray(key);

		for (final JsonValue jsonHost : jsonHosts) {
			HostName host = new HostName(((JsonString) jsonHost).getString());

			if (!host.isValid()) {
				throw new InvalidHostException(((JsonString) jsonHost).getString()
						+ " is an invalid host");
			}

			hosts.add(host);
		}

		return hosts;
	}

}
