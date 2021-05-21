/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.stack;

import org.privacyinternational.thornsec.core.data.AData;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule.Encapsulation;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.InvalidIPAddressException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPortException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidServerException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.InvalidNetworkInterfaceException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidMachineModelException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidServerModelException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.NetworkInterfaceModel;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;
import org.privacyinternational.thornsec.core.model.network.UserModel;
import org.privacyinternational.thornsec.core.profile.AStructuredProfile;
import org.privacyinternational.thornsec.core.unit.SimpleUnit;
import org.privacyinternational.thornsec.core.unit.fs.FileUnit;
import org.privacyinternational.thornsec.core.unit.pkg.InstalledUnit;

import javax.json.Json;
import javax.json.JsonObject;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

/**
 * This builds a WireGuard server on a given machine (intended to be run on a
 * Router).
 */
public class WireGuard extends AStructuredProfile {

	/**
	 * This model creates a WireGuard interface through systemd-networkd.
	 *
	 * For more information, see https://www.wireguard.com/
	 */
	public class WireGuardModel extends NetworkInterfaceModel {

		private Collection<UserModel> peers;
		private Integer listenPort;

		public WireGuardModel(NetworkInterfaceData myData, NetworkModel networkModel) throws InvalidNetworkInterfaceException, InvalidIPAddressException {
			super(myData, networkModel);

			setInet(NetworkInterfaceData.Inet.WIREGUARD);
			setWeighting(20);
		}

		public void setListenPort(Integer listenPort) {
			this.listenPort = listenPort;
		}

		@Override
		public Optional<FileUnit> getNetDevFile() {
			FileUnit netdev = super.getNetDevFile().get();

			netdev.appendCarriageReturn();
			netdev.appendLine("[WireGuard]");
			netdev.appendLine("PrivateKey=$(cat /etc/wireguard/private.key)");
			netdev.appendLine("ListenPort=" + this.listenPort);

			this.peers.forEach((peer) -> {
				netdev.appendCarriageReturn();
				netdev.appendLine("[WireGuardPeer]");
				netdev.appendLine("PublicKey=" + peer.getWireGuardKey().orElseGet(() -> ""));
				netdev.appendLine("PresharedKey=" + peer.getWireguardPSK().orElseGet(() -> ""));
				netdev.appendLine("AllowedIPs=" + String.join(", ", peer.getWireGuardIPs().orElseGet(() -> new ArrayList<>())));
				netdev.appendLine("Description=" + peer.getUsername());
			});

			return Optional.of(netdev);
		}

		@Override
		public Optional<FileUnit> getNetworkFile() {
			return Optional.empty(); //No network file here
		}

		public void addWireGuardPeer(UserModel user) {
			if (this.peers == null) {
				this.peers = new ArrayList<>();
			}

			this.peers.add(user);
		}
	}

	private class WireGuardConfig extends AData {
		public WireGuardConfig(JsonObject wireguardData) throws ADataException {
			super("wireguard", null, wireguardData);
		}

		/**
		 * Port WireGuard should be listening on
		 */
		public int getListenPort() {
			return getData().getInt("listen_port", 51820);
		}

		@Override
		public AData read(JsonObject data) throws ADataException {
			return null;
		}
	}

	private WireGuardConfig data;

	public WireGuard(ServerModel me) {
		super(me);
	}

	private WireGuard.WireGuardConfig getMyConfig() {
		if (null == this.data) {
			try {
				this.data = new WireGuardConfig(getServerModel().getData().getData());
			} catch (ADataException e) {
				e.printStackTrace();
			}
		}
		return this.data;
	}

	@Override
	public final Collection<IUnit> getInstalled() throws InvalidServerModelException {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new InstalledUnit("wireguard", "proceed", "wireguard"));

		return units;
	}

	@Override
	public final Collection<IUnit> getPersistentConfig()
			throws InvalidServerException, InvalidIPAddressException, InvalidMachineModelException {
		final Collection<IUnit> units = new ArrayList<>();

		WireGuardModel nic = null;
		try {
			nic = new WireGuardModel(new NetworkInterfaceData("wireguard", null, Json.createObjectBuilder().build()), getNetworkModel());
		} catch (InvalidNetworkInterfaceException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ADataException e) {
			e.printStackTrace();
		}

		for (UserModel user : getNetworkModel().getUsers()) {
			nic.addWireGuardPeer(user);
		}

		nic.setListenPort(getMyConfig().getListenPort());
		//TODO
		//nic.addAddress(getNetworkModel().getSubnet(MachineType.VPN));

		getMachineModel().addNetworkInterface(nic);

		units.add(new SimpleUnit("wireguard_private_key", "wireguard_installed",
				"echo $(wg genkey) | sudo tee /etc/wireguard/private.key > /dev/null",
				"sudo cat /etc/wireguard/private.key 2>&1;", "", "fail",
				"I was unable to generate you a private key."));

		return units;
	}

	@Override
	public final Collection<IUnit> getPersistentFirewall() throws InvalidPortException {
		final Collection<IUnit> units = new ArrayList<>();

		getServerModel().addListen(Encapsulation.UDP, getMyConfig().getListenPort());

		return units;
	}
}
