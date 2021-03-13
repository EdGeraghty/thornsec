/*
 * This code is part of the ThornSec project.
 * 
 * To learn more, please head to its GitHub repo: @privacyint
 * 
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data;

//import static org.junit.jupiter.api.Assertions.assertNotNull;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import javax.json.JsonObject;
import javax.json.stream.JsonParsingException;

import org.privacyinternational.thornsec.core.exception.data.ADataException;

/**
 * Abstract class for something representing "Data" on our network.
 * 
 * This is something which has been read() from a JSON, and for our purposes
 * acts as a DAO.
 */
public class AData {

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
	 * @throws IOException
	 * @throws JsonParsingException
	 * @throws URISyntaxException
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
		////assertNotNull(this.label);

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
	 * Sets the object's data.
	 *
	 * @param data the new data
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

}
}
