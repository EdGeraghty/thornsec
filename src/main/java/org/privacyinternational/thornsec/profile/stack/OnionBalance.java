/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.stack;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import org.privacyinternational.thornsec.core.exception.data.InvalidPortException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPropertyArrayException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidMachineException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidMachineModelException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.profile.AStructuredProfile;
import org.privacyinternational.thornsec.core.unit.SimpleUnit;
import org.privacyinternational.thornsec.core.unit.fs.DirUnit;
import org.privacyinternational.thornsec.core.unit.fs.FileUnit;
import org.privacyinternational.thornsec.core.unit.pkg.InstalledUnit;
import org.privacyinternational.thornsec.core.unit.pkg.RunningUnit;
import inet.ipaddr.HostName;

public class OnionBalance extends AStructuredProfile {

	private Set<String> backends;

	public OnionBalance(ServerModel me) {
		super(me);
	}

	@Override
	public Collection<IUnit> getInstalled() throws InvalidMachineModelException {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new InstalledUnit("tor_keyring", "tor_pgp", "deb.torproject.org-keyring"));
		units.add(new InstalledUnit("tor", "tor_keyring_installed", "tor"));

		units.add(new InstalledUnit("onionbalance", "tor_installed", "onionbalance"));

		getServerModel().getUserModel().addUsername("debian-tor");
		getServerModel().getUserModel().addUsername("onionbalance");

		return units;
	}

	@Override
	public Collection<IUnit> getPersistentConfig() throws InvalidMachineModelException {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new DirUnit("onionbalance_var_run", "onionbalance_installed", "/var/run/onionbalance"));

		final FileUnit service = new FileUnit("onionbalance_service", "onionbalance_installed",
				"/lib/systemd/system/onionbalance.service");
		units.add(service);

		service.appendLine("[Unit]");
		service.appendLine("Description=OnionBalance - Tor Onion Service load balancer");
		service.appendLine("Documentation=man:onionbalance");
		service.appendLine("Documentation=file:///usr/share/doc/onionbalance/html/index.html");
		service.appendLine("Documentation=https://github.com/DonnchaC/onionbalance");
		service.appendLine("After=network.target, tor.service");
		service.appendLine("Wants=network-online.target");
		service.appendLine("ConditionPathExists=/etc/onionbalance/config.yaml");
		service.appendCarriageReturn();
		service.appendLine("[Service]");
		service.appendLine("Type=simple");
		service.appendLine("PIDFile=/run/onionbalance.pid");
		service.appendLine("Environment=\"ONIONBALANCE_LOG_LOCATION=/var/log/onionbalance/log\"");
		service.appendLine("ExecStartPre=/bin/chmod o+r /var/run/tor/control.authcookie");
		// service.appendLine("ExecStartPre=/bin/chmod o+r /var/run/tor/control");
		service.appendLine("ExecStartPre=/bin/mkdir -p /var/run/onionbalance");
		service.appendLine("ExecStartPre=/bin/chown -R onionbalance:onionbalance /var/run/onionbalance");
		service.appendLine("ExecStart=/usr/sbin/onionbalance -c /etc/onionbalance/config.yaml");
		service.appendLine("ExecReload=/usr/sbin/onionbalance reload");
		service.appendLine(
				"ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry=TERM/5/KILL/5 --pidfile /run/onionbalance.pid");
		service.appendLine("TimeoutStopSec=5");
		service.appendLine("KillMode=mixed");
		service.appendCarriageReturn();
		service.appendLine("EnvironmentFile=-/etc/default/%p");
		service.appendLine("User=onionbalance");
		service.appendLine("PermissionsStartOnly=true");
		service.appendLine("Restart=always");
		service.appendLine("RestartSec=10s");
		service.appendLine("LimitNOFILE=65536");
		service.appendCarriageReturn();
		service.appendLine("NoNewPrivileges=yes");
		service.appendLine("PrivateDevices=yes");
		service.appendLine("PrivateTmp=yes");
		service.appendLine("ProtectHome=yes");
		service.appendLine("ProtectSystem=full");
		service.appendLine("ReadOnlyDirectories=/");
		service.appendLine("ReadWriteDirectories=-/proc");
		service.appendLine("ReadWriteDirectories=-/var/log/onionbalance");
		service.appendLine("ReadWriteDirectories=-/var/run");
		service.appendCarriageReturn();
		service.appendLine("[Install]");
		service.appendLine("WantedBy=multi-user.target");

		final FileUnit torrc = new FileUnit("torrc", "tor_installed", "/etc/tor/torrc");
		units.add(torrc);

		torrc.appendLine("Datadirectory /var/lib/tor");
		torrc.appendLine("ControlPort 9051");
		torrc.appendLine("CookieAuthentication 1");
		torrc.appendLine("SocksPort 0");
		torrc.appendCarriageReturn();
		torrc.appendLine("RunAsDaemon 1");
		torrc.appendCarriageReturn();
		torrc.appendLine("FascistFirewall 1");

		units.add(new SimpleUnit("tor_service_enabled", "torrc", "sudo systemctl enable tor",
				"sudo systemctl is-enabled tor", "enabled", "pass",
				"Couldn't set tor to auto-start on boot.  You will need to manually start the service (\"sudo service tor start\") on reboot."));

		units.add(new SimpleUnit("onionbalance_service_enabled", "onionbalance_service_config",
				"sudo systemctl enable onionbalance", "sudo systemctl is-enabled onionbalance", "enabled", "pass",
				"Couldn't set onionbalance to auto-start on boot.  You will need to manually start the service (\"sudo service onionbalance start\") on reboot."));

		return units;
	}

	@Override
	public Collection<IUnit> getLiveConfig()
			throws InvalidPropertyArrayException, InvalidMachineException, InvalidMachineModelException {
		final Collection<IUnit> units = new ArrayList<>();

		final FileUnit onionbalanceConfig = new FileUnit("onionbalance", "onionbalance_installed",
				"/etc/onionbalance/config.yaml");
		units.add(onionbalanceConfig);

		onionbalanceConfig.appendLine("REFRESH_INTERVAL: 600");
		onionbalanceConfig.appendLine("services:");
		onionbalanceConfig.appendLine("    - key: /media/data/onionbalance/private_key");
		onionbalanceConfig.appendLine("      instances:");

		final Set<String> backends = getBackends();
		for (final String backend : backends) {
			onionbalanceConfig.appendLine("        - address: " + backend);
		}

		units.add(new RunningUnit("tor", "tor", "/usr/bin/tor"));
		getServerModel().addProcessString(
				"/usr/bin/tor --defaults-torrc /usr/share/tor/tor-service-defaults-torrc -f /etc/tor/torrc --RunAsDaemon 0$");

		return units;
	}

	public void putBackend(String... backends) {
		if (this.backends == null) {
			this.backends = new LinkedHashSet<>();
		}

		for (final String backend : backends) {
			this.backends.add(backend);
		}
	}

	private Set<String> getBackends() {
		return this.backends;
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws InvalidPortException {
		final Collection<IUnit> units = new ArrayList<>();

		//getServerModel().getAptSourcesModel().addAptSource("tor",
		//		"deb http://deb.torproject.org/torproject.org buster main", "keys.gnupg.net",
		//		"A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89");
		getServerModel().addEgress(new HostName("*")); // Needs to be able to call out to everywhere

		return units;
	}

}
