/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.network;

import org.privacyinternational.thornsec.core.data.network.NetworkData;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.InvalidJSONException;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map.Entry;

/**
 * This is the model at the very heart of ThornSec.
 *
 * This model initialises and populates our various networks.
 */
public class ThornsecModel {

	private final Collection<NetworkModel> networks;

	public ThornsecModel() {
		this.networks = new ArrayList<>();
	}

	/**
	 * Read in JSON 
	 * @param filePath
	 * @throws ADataException 
	 */
	public void read(String filePath) throws AThornSecException {
		Path configFilePath = Paths.get(filePath);

		String rawText;

		// Start by stripping comments out of the JSON
		try {
			byte[] raw = Files.readAllBytes(configFilePath);
			rawText = new String(raw, StandardCharsets.UTF_8);
			rawText = rawText.replaceAll("(?:/\\*(?:[^*]|(?:\\*+[^*/]))*\\*+/)|(?://.*)", "");
		}
		catch (IOException e) {
			throw new InvalidJSONException("Unable to read the file at " + filePath);
		}

		JsonReader jsonReader = Json.createReader(new StringReader(rawText));
		JsonObject networks = jsonReader.readObject();

		for (final Entry<String, JsonValue> network : networks.entrySet()) {
			final NetworkData networkData = new NetworkData(network.getKey(), Path.of(filePath), (JsonObject) network.getValue());

			this.networks.add(new NetworkModel(networkData));
		}
	}

	/**
	 * Returns our various networks
	 * @return a collection of all networks in our ThornSec model
	 */
	public Collection<NetworkModel> getNetworks() {
		return this.networks;
	}

	/**
	 * Get a specific network by its label
	 * @param label The network's label, as given in the JSON
	 * @return the corresponding NetworkModel
	 */
	public NetworkModel getNetwork(String label) {
		return getNetworks().stream()
				.filter(
					network -> network.getLabel().equals(label)
				)
				.findFirst()
				.get();
	}
}
