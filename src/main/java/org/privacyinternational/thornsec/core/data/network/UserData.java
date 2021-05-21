/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data.network;

import org.privacyinternational.thornsec.core.data.AData;
import org.privacyinternational.thornsec.core.exception.data.ADataException;

import javax.json.JsonArray;
import javax.json.JsonObject;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

/**
 * This class represents a User.
 * 
 * Users have several properties
 */
public class UserData extends AData {

	private String username;
	private String fullName;
	private String sshKey;
	private String homeDir;
	private String defaultPassword;
	private String wireguardKey;
	private Collection<String> wireguardIPs;
	private String wireguardPSK;

	/**
	 * Create a new UserData populated with null values
	 * @param label
	 */
	public UserData(String label, Path filePath, JsonObject data) throws ADataException {
		super(label, filePath, data);
	}

	@Override
	public UserData read(JsonObject data) throws ADataException {
		super.read(data);

		this.username = data.getString("username", null);
		this.fullName = data.getString("fullname", "Dr McNuggets");
		this.sshKey = data.getString("ssh", null);
		this.homeDir = data.getString("home_dir", null);
		this.defaultPassword = data.getString("defaultpw", null);

		readWireguard(data); //TODO: move this out to WireGuard. It doesn't belong here

		return this;
	}

	private void readWireguard(JsonObject data) {
		if (!data.containsKey("wireguard")) {
			return;
		}

		JsonObject wireguardData = data.getJsonObject("wireguard");

		this.wireguardKey = wireguardData.getString("key", null);
		this.wireguardPSK = wireguardData.getString("psk", null);

		if (!wireguardData.containsKey("ips")) {
			return;
		}

		final JsonArray ips = wireguardData.getJsonArray("ips");
		this.wireguardIPs = new ArrayList<>();

		for (int i = 0; i < ips.size(); ++i) {
			this.wireguardIPs.add(ips.getString(i));
		}
	}

	/**
	 * Get a User's full name, if set
	 * @return 
	 */
	public final Optional<String> getFullName() {
		return Optional.ofNullable(this.fullName);
	}

	/**
	 * Get a User's home directory, if set
	 */
	public final Optional<String> getHomeDirectory() {
		return Optional.ofNullable(this.homeDir);
	}
	
	/**
	 * Get a User's WireGuard public key, if set
	 * @return
	 */
	public final Optional<String> getWireGuardKey() {
		return Optional.ofNullable(this.wireguardKey);
	}

	/**
	 * Get a User's WireGuard IP address, if set
	 * @return
	 */
	public final Optional<Collection<String>> getWireGuardIPs() {
		return Optional.ofNullable(this.wireguardIPs);
	}

	/**
	 * Get a User's WireGuard PreShared Key, if set
	 * @return
	 */
	public Optional<String> getWireGuardPSK() {
		return Optional.ofNullable(this.wireguardPSK);
	}

	/**
	 * Get a User's SSH public key, if set
	 * @return
	 */
	public final Optional<String> getSSHKey() {
		return Optional.ofNullable(this.sshKey);
	}

	/**
	 * Get a User's default passphrase, if set
	 * @return
	 */
	public final Optional<String> getDefaultPassphrase() {
		return Optional.ofNullable(this.defaultPassword);
	}

	/**
	 * Get a User's username, if set
	 * @return
	 */
	public Optional<String> getUsername() {
		return Optional.ofNullable(this.username);
	}
}
