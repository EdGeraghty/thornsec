/*
 * This code is part of the ThornSec project.
 * 
 * To learn more, please head to its GitHub repo: @privacyint
 * 
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data;

import inet.ipaddr.HostName;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.InvalidHostException;

import javax.json.*;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

/**
 * Abstract class for something representing "Data" on our network.
 * 
 * This is something which has been read() from a JSON, and for our purposes
 * acts as a DAO.
 */
public abstract class AData {

	private final String label;
	private final Path filePath;
	private JsonObject data;

	/**
	 * Instantiates a new data object. Automatically reads().
	 *
	 * @param label the label for this object
	 */
	public AData(String label, Path filePath, JsonObject data) throws ADataException {
		this.label = label;
		this.filePath = filePath;
		this.data = data;

		read(data);
	}

	/**
	 * JSON read method. Updates the underlying data with read values
	 *
	 * @param data the JSON data
	 * @return populated AData object
	 * @throws ADataException if something is wrong with the Data
	 */
	public AData read(JsonObject data) throws ADataException {
		JsonObject currentData = getData();

		JsonObjectBuilder newData = Json.createObjectBuilder();
		currentData.forEach(newData::add);
		data.forEach(newData::add);

		setData(newData.build());

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
	 * Gets the object's raw JSON data.
	 *
	 * Think carefully about if this is *actually* what you want!
	 *
	 * @return the raw data, as a JsonObject
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
	 * Get the path to the original JSON which configured me
	 * @return a Path to the original JSON
	 */
	public final Path getFilePath() {
		return this.filePath;
	}

}
