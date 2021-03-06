/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.service.web;

import java.util.ArrayList;
import java.util.Collection;

import org.privacyinternational.thornsec.core.exception.data.InvalidPortException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPropertyArrayException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPropertyException;
import org.privacyinternational.thornsec.core.exception.data.MissingPropertiesException;
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
import org.privacyinternational.thornsec.profile.stack.Nginx;

/**
 * This profile will put an onion address in front of website(s)
 */
public class TorHS extends AStructuredProfile {

	private final Webproxy proxy;

	public TorHS(ServerModel me) throws MissingPropertiesException {
		super(me);

		this.proxy = new Webproxy(me);
	}

	@Override
	public Collection<IUnit> getInstalled() throws InvalidMachineModelException {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new InstalledUnit("tor_keyring", "tor_pgp", "deb.torproject.org-keyring"));
		units.add(new InstalledUnit("tor", "tor_keyring_installed", "tor"));

		getServerModel().getUserModel().addUsername("debian-tor");

		units.addAll(this.proxy.getInstalled());

		return units;
	}

	@Override
	public Collection<IUnit> getPersistentConfig() throws InvalidPropertyArrayException, InvalidMachineException,
			InvalidPropertyException, InvalidMachineModelException {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new DirUnit("torhs_files_dir", "tor_installed", "/var/lib/tor/hidden_service"));

		units.add(new SimpleUnit("torhs_hostname", "tor_data_mounted",
				// Copy over the new hostname file if one doesn't already exist, or replace the
				// new hostname if we already have one
				"sudo [ ! -f /media/data/tor/hostname ] && cp /var/lib/tor/hidden_service/hostname /media/data/tor/hostname || cp /media/data/tor/hostname /var/lib/tor/hidden_service/hostname",
				"sudo cmp --silent /media/data/tor/hostname /var/lib/tor/hidden_service/hostname && echo pass || echo fail",
				"pass", "pass"));

		units.add(new SimpleUnit("torhs_private_key", "tor_data_mounted",
				// Copy over the new private key file if one doesn't already exist, or replace
				// the new private key if we already have one
				"sudo [ ! -f /media/data/tor/private_key ] && cp /var/lib/tor/hidden_service/private_key /media/data/tor/private_key || cp /media/data/tor/private_key /var/lib/tor/hidden_service/private_key",
				"sudo cmp --silent /media/data/tor/private_key /var/lib/tor/hidden_service/private_key && echo pass || echo fail",
				"pass", "pass"));

		/*
		 * String service = ""; service.appendLine("[Unit]"); service +=
		 * "Description=nginx - high performance web server"); service +=
		 * "Documentation=http://nginx.org/en/docs/"); service +=
		 * "After=network-online.target remote-fs.target nss-lookup.target"); service
		 * .appendLine("Wants=network-online.target"); service.appendCarriageReturn();
		 * service += "[Service]"); service.appendLine("Type=forking"); service +=
		 * "PIDFile=/var/run/nginx.pid"); service +=
		 * "ExecStartPre=/bin/rm -f /media/data/www/port-80.sock /media/data/www/port-443.sock\n"
		 * ; service.appendLine("ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf");
		 * service .appendLine("ExecReload=/bin/kill -s HUP $MAINPID"); service +=
		 * "ExecStop=/bin/kill -s TERM $MAINPID"); service.appendCarriageReturn();
		 * service += "[Install]"); service.appendLine("WantedBy=multi-user.target";
		 *
		 * units.add(new FileUnit("nginx_service", "nginx_installed", service,
		 * "/etc/systemd/system/multi-user.target.wants/nginx.service"));
		 */
		// Configs here loosely based on the eotk (c) Alec Muffet
		// https://github.com/alecmuffett/eotk
		// Released under GPL v3 https://github.com/alecmuffett/eotk/blob/master/LICENSE

		final FileUnit torConfig = new FileUnit("tor_config", "tor_installed", "/etc/tor/torrc");
		units.add(torConfig);
		torConfig.appendLine("DataDirectory /var/lib/tor");
		torConfig.appendLine("ControlPort unix:/var/lib/tor/tor-control.sock");
		torConfig.appendLine("PidFile /var/lib/tor/tor.pid");
		torConfig.appendLine("SafeLogging 1");
		torConfig.appendLine("LongLivedPorts 80,443");
		torConfig.appendLine("HeartbeatPeriod 60 minutes");
		torConfig.appendLine("RunAsDaemon 1");
		torConfig.appendCarriageReturn();
		torConfig.appendLine("SocksPort 0");
		torConfig.appendCarriageReturn();
		torConfig.appendLine("HiddenServiceDir /var/lib/tor/hidden_service/");
		torConfig.appendLine("HiddenServicePort 80 unix:/var/lib/tor/port-80.sock");
		torConfig.appendLine("HiddenServicePort 443 unix:/var/lib/tor/port-443.sock");
		torConfig.appendLine("HiddenServiceNumIntroductionPoints 3");
		torConfig.appendCarriageReturn();
		torConfig.appendLine("FascistFirewall 1");

		units.add(new SimpleUnit("tor_service_enabled", "tor_config", "sudo systemctl enable tor",
				"sudo systemctl is-enabled tor", "enabled", "pass",
				"Couldn't set tor to auto-start on boot.  You will need to manually start the service (\"sudo service tor start\") on reboot."));

		final FileUnit proxyConfig = new FileUnit("tor_nginx_config", "tor_installed",
				Nginx.DEFAULT_CONFIG_FILE.toString());
		proxyConfig.appendLine("include /etc/nginx/includes/ssl_params;");
		proxyConfig.appendLine("proxy_buffering on;");
		proxyConfig.appendLine("proxy_buffers 16 64k;");
		proxyConfig.appendLine("proxy_buffer_size 64k;");
		proxyConfig.appendLine("proxy_busy_buffers_size 512k;");
		proxyConfig.appendLine("proxy_max_temp_file_size 2048k;");
		proxyConfig.appendLine("proxy_temp_file_write_size 64k;");
		proxyConfig.appendLine("proxy_temp_path \\\"/tmp\\\";");
		proxyConfig.appendCarriageReturn();
		proxyConfig.appendLine("allow \\\"unix:\\\";");
		proxyConfig.appendLine("deny all;");
		proxyConfig.appendCarriageReturn();
		proxyConfig.appendLine("proxy_read_timeout 60;");
		proxyConfig.appendLine("proxy_connect_timeout 60;");
		proxyConfig.appendCarriageReturn();
		proxyConfig.appendLine("proxy_cache_path /tmp/nginx-cache-torhs levels=1:2 keys_zone=torhs:64m;");
		proxyConfig.appendLine("proxy_cache torhs;");
		proxyConfig.appendLine("proxy_cache_min_uses 1;");
		proxyConfig.appendLine("proxy_cache_revalidate on;");
		proxyConfig.appendLine("proxy_cache_use_stale timeout updating;");
		proxyConfig.appendLine("proxy_cache_valid any 60s;");
		proxyConfig.appendCarriageReturn();
		proxyConfig.appendLine("server {");
		proxyConfig.appendLine("    server_name _ default;");
		proxyConfig.appendCarriageReturn();
		// proxyConfig.appendLine(" listen unix:/media/data/www/port-80.sock;");
		proxyConfig.appendLine("    listen unix:/var/lib/tor/port-80.sock;");
		proxyConfig.appendLine("    return 307 https://\\$host\\$request_uri;");
		proxyConfig.appendLine("}");
		proxyConfig.appendCarriageReturn();
		proxyConfig.appendLine("server {");
		proxyConfig.appendLine("    server_name _ default;");
		proxyConfig.appendCarriageReturn();
		// proxyConfig.appendLine(" listen unix:/media/data/www/port-443.sock ssl;");
		proxyConfig.appendLine("    listen unix:/var/lib/tor/port-443.sock ssl;");
		proxyConfig.appendCarriageReturn();
		proxyConfig.appendLine("    ssl_certificate /media/data/tls/fullchain.pem;");
		proxyConfig.appendLine("    ssl_certificate_key /media/data/tls/privkey.pem;");
		proxyConfig.appendLine("    ssl_ciphers 'EECDH+CHACHA20:EECDH+AESGCM:EECDH+AES256';");
		proxyConfig.appendLine("    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;");
		proxyConfig.appendLine("    ssl_session_cache shared:SSL:10m;");
		proxyConfig.appendLine("    ssl_session_timeout 10m;");
		proxyConfig.appendLine("    ssl_buffer_size 4k;");
		proxyConfig.appendLine("    ssl_prefer_server_ciphers on;");
		proxyConfig.appendLine("    ssl_ecdh_curve secp384r1:prime256v1;");
		proxyConfig.appendCarriageReturn();
		proxyConfig.appendLine("    location / {");
		// TODO: fixme
		// proxyConfig.appendLine(" proxy_pass \\\"\\$scheme://" +
		// backendIP.toFullString() + "\\\"");
		proxyConfig.appendLine("        proxy_http_version 1.1;");
		proxyConfig.appendLine("        proxy_set_header Accept-Encoding \\\"identity\\\";");
		proxyConfig.appendLine("        proxy_set_header Connection \\\"upgrade\\\";");
		proxyConfig.appendLine("        proxy_set_header Upgrade \\\"upgrade\\\";");
		proxyConfig.appendLine("        proxy_ssl_server_name on;");
		proxyConfig.appendLine("        proxy_set_header Host $host;");
		proxyConfig.appendLine("    }");
		proxyConfig.appendLine("    include /media/data/nginx_custom_conf_d/default.conf;");
		proxyConfig.appendLine("}");

		this.proxy.setLiveConfig(proxyConfig);

		units.addAll(this.proxy.getPersistentConfig());

		return units;
	}

	@Override
	public Collection<IUnit> getLiveConfig() throws InvalidMachineModelException, InvalidPropertyArrayException,
			InvalidMachineException, MissingPropertiesException {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new RunningUnit("tor", "tor", "/usr/bin/tor"));
		getServerModel().addProcessString(
				"/usr/bin/tor --defaults-torrc /usr/share/tor/tor-service-defaults-torrc -f /etc/tor/torrc --RunAsDaemon 0$");
		units.addAll(this.proxy.getLiveConfig());

		return units;
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws InvalidMachineModelException, InvalidPortException,
			InvalidPropertyArrayException, InvalidMachineException {
		final Collection<IUnit> units = new ArrayList<>();

		units.addAll(this.proxy.getPersistentFirewall());

		//getServerModel().getAptSourcesModel().addAptSource("tor",
		//		"deb http://deb.torproject.org/torproject.org buster main", "keys.gnupg.net",
		//		"A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89");

		// Allow the server to call out everywhere on :80 & :443
		getMachineModel().addEgress(new HostName("255.255.255.255:80"));
		getMachineModel().addEgress(new HostName("255.255.255.255"));

		return units;
	}
}
