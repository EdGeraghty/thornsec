/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.service.machine;

import java.util.ArrayList;
import java.util.Collection;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule.Encapsulation;
import org.privacyinternational.thornsec.core.exception.data.InvalidPortException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidMachineException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidMachineModelException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidServerModelException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.model.network.UserModel;
import org.privacyinternational.thornsec.core.profile.AStructuredProfile;
import org.privacyinternational.thornsec.core.unit.SimpleUnit;
import org.privacyinternational.thornsec.core.unit.fs.DirUnit;
import org.privacyinternational.thornsec.core.unit.fs.FileUnit;
import org.privacyinternational.thornsec.core.unit.pkg.InstalledUnit;
import org.privacyinternational.thornsec.core.unit.pkg.RunningUnit;

/**
 * This configures our SSH daemon.
 */
public class SSH extends AStructuredProfile {

	public SSH(ServerModel me) {
		super(me);
	}

	@Override
	public Collection<IUnit> getInstalled() {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new InstalledUnit("sshd", "proceed", "openssh-server"));

		return units;
	}

	/**
	 * See https://man.openbsd.org/sshd_config
	 */
	@Override
	public Collection<IUnit> getPersistentConfig() throws InvalidServerModelException, InvalidMachineException {
		final Collection<IUnit> units = new ArrayList<>();

		// The below is informed by https://infosec.mozilla.org/guidelines/openssh

		final FileUnit sshdConf = new FileUnit("sshd_config", "sshd_installed", "/etc/ssh/sshd_config");
		units.add(sshdConf);

		sshdConf.appendLine("Port " + getServerModel().getSSHListenPort());
		// sshdConf.appendLine((((ServerModel)me).isRouter()) ? "ListenAddress " +
		// networkModel.getData().getIP().getHostAddress() + "\n" : "";
		sshdConf.appendLine("Protocol 2");
		// sshdConf.appendLine("HostKey /etc/ssh/ssh_host_rsa_key");
		sshdConf.appendLine("HostKey /etc/ssh/ssh_host_ed25519_key");
		sshdConf.appendLine(
				"MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com");
		sshdConf.appendLine(
				"Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr");
		sshdConf.appendLine(
				"KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256");
		sshdConf.appendLine("SyslogFacility AUTH");
		sshdConf.appendLine("# LogLevel VERBOSE logs the key fingerprint - useul for auditing");
		sshdConf.appendLine("LogLevel VERBOSE");
		sshdConf.appendLine("LoginGraceTime 120");
		sshdConf.appendLine("PermitRootLogin no");
		sshdConf.appendLine("StrictModes yes");
		sshdConf.appendLine("AuthenticationMethods publickey");
		sshdConf.appendLine("PubkeyAuthentication yes");
		sshdConf.appendLine("PasswordAuthentication no");
		sshdConf.appendLine("AuthorizedKeysFile %h/.ssh/authorized_keys");
		sshdConf.appendLine("IgnoreRhosts yes");
		sshdConf.appendLine("HostbasedAuthentication no");
		sshdConf.appendLine("PermitEmptyPasswords no");
		sshdConf.appendLine("ChallengeResponseAuthentication no");
		sshdConf.appendLine("X11Forwarding yes");
		sshdConf.appendLine("X11DisplayOffset 10");
		sshdConf.appendLine("PrintMotd no"); // This is handled by PAM anyway
		sshdConf.appendLine("PrintLastLog yes");
		sshdConf.appendLine("TCPKeepAlive yes");
		sshdConf.appendLine("AcceptEnv LANG LC_*");
		sshdConf.appendLine(
				"# Log sftp level file access (read/write/etc.) that would not be easily logged otherwise.");
		sshdConf.appendLine("Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO");
		sshdConf.appendLine("UsePAM yes");
		sshdConf.appendLine("Banner /etc/ssh/sshd_banner");
		sshdConf.appendLine("MaxSessions 1");
		sshdConf.appendLine("UseDNS no");

		// this.networkModel.getServerModel(getLabel()).getConfigsModel().addConfigFilePath("/etc/ssh/sshd_config");

		// This banner is taken from
		// https://www.dedicatedukhosting.com/hosting/adding-ssh-welcome-and-warning-messages/
		final FileUnit banner = new FileUnit("sshd_banner", "proceed", "/etc/ssh/banner");
		units.add(banner);

		banner.appendLine("************************NOTICE***********************");
		banner.appendLine("This system is optimised and configured with security and logging as a");
		banner.appendLine("priority. All user activity is logged and streamed offsite. Individuals");
		banner.appendLine("or groups using this system in excess of their authorisation will have");
		banner.appendLine("all access terminated. Illegal access of this system or attempts to");
		banner.appendLine("limit or restrict access to authorised users (such as DoS attacks) will");
		banner.appendLine("be reported to national and international law enforcement bodies. We");
		banner.appendLine("will prosecute to the fullest extent of the law regardless of the funds");
		banner.appendLine("required. Anyone using this system consents to these terms and the laws");
		banner.appendLine("of the United Kingdom and United States respectively.");
		banner.appendLine("************************NOTICE***********************");

		// this.networkModel.getServerModel(getLabel()).getConfigsModel().addConfigFilePath("/etc/ssh/banner");

		units.add(new DirUnit("motd", "proceed", "/etc/update-motd.d/"));

		// Elements of this motd banner are taken from
		// https://nickcharlton.net/posts/debian-ubuntu-dynamic-motd.html
		// (c) 2009-2010 Canonical Ltd
		// (c) 2013 Nick Charlton
		// Released under GPL
		final FileUnit motd = new FileUnit("sshd_motd", "proceed", "/etc/update-motd.d/00-motd");
		units.add(motd);

		motd.appendLine("#!/bin/bash");
		motd.appendLine("echo \\\"This machine is a Thornsec configured machine.\\\"");
		motd.appendLine("echo \\\"_Logging in to configure this machine manually is highly discouraged!_\\\"");
		motd.appendLine("echo \\\"Please only continue if you know what you're doing!\\\"");
		motd.appendLine("echo");
		motd.appendLine("date=\\`date\\`");
		motd.appendLine("load=\\`cat /proc/loadavg | awk '{print \\$1}'\\`");
		motd.appendLine("root_usage=\\`df -h / | awk '/\\\\// {print \\$(NF-1)}'\\`");
		motd.appendLine("memory_usage=\\`free -m | awk '/Mem/ { printf(\\\"%3.1f%%\\\", \\$3/\\$2*100) }'\\`");
		motd.appendLine("swap_usage=\\`free -m | awk '/Swap/ { printf(\\\"%3.1f%%\\\", \\$3/\\$2*100) }'\\`");
		motd.appendLine("users=\\`users | wc -w\\`");
		motd.appendLine("echo \\\"System information as of: \\${date}\\\"");
		motd.appendLine("echo");
		motd.appendLine("printf \\\"System load:\\\\t%s\\\\tMemory usage:\\\\t%s\\\\n\\\" \\${load} \\${memory_usage}");
		motd.appendLine("printf \\\"Usage on /:\\\\t%s\\\\tSwap usage:\\\\t%s\\\\n\\\" \\${root_usage} \\${swap_usage}");
		motd.appendLine("printf \\\"Currently logged in users:\\\\t%s\\\\n\\\" \\${users}");
		motd.appendLine("echo");
		motd.appendLine("echo \\\"HERE BE DRAGONS.\\\"");
		motd.appendCarriageReturn();

		// this.networkModel.getServerModel(getLabel()).getConfigsModel().addConfigFilePath("/etc/update-motd.d/00-motd");
		//units.add(new FilePermsUnit("sshd_motd_perms", "sshd_motd", "/etc/update-motd.d/00-motd", "755"));

		// units.add(new SimpleUnit("sshd_rsa", "sshd_config",
		// "echo -e \"y\\n\" | sudo ssh-keygen -f /etc/ssh/ssh_host_rsa_key -N \"\" -t
		// rsa -b 4096",
		// "sudo ssh-keygen -lf /etc/ssh/ssh_host_rsa_key | awk '{print $1}'", "4096",
		// "pass",
		// "Couldn't generate you a new SSH key. This isn't too bad, but try re-running
		// the script to get it to work."));

		// Secure sshd as per
		// https://stribika.github.io/2015/01/04/secure-secure-shell.html
		units.add(new SimpleUnit("sshd_ed25519", "sshd_config",
				"echo -e \"y\\\\n\" | sudo ssh-keygen -f /etc/ssh/ssh_host_ed25519_key -N \"\" -t ed25519",
				"sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key | awk '{print $1}'", "256", "pass",
				"Couldn't generate you a strong ed25519 SSH key.  This isn't too bad, but try re-running the script to get it to work."));

		units.add(new SimpleUnit("sshd_moduli_exists", "sshd_config",
				"sudo ssh-keygen -G /etc/ssh/moduli.all -b 4096;"
						+ "sudo ssh-keygen -T /etc/ssh/moduli.safe -f /etc/ssh/moduli.all;"
						+ "sudo mv /etc/ssh/moduli.safe /etc/ssh/moduli;" + "sudo rm /etc/ssh/moduli.all",
				"cat /etc/ssh/moduli", "", "fail",
				"Couldn't generate new moduli for your SSH daemon.  This is undesirable, please try re-running the script."));

		units.add(new SimpleUnit("sshd_moduli_not_weak", "sshd_moduli_exists",
				"awk '$5 > 3071' /etc/ssh/moduli > /tmp/moduli;" + "sudo mv /tmp/moduli /etc/ssh/moduli;",
				"awk '$5 <= 3071' /etc/ssh/moduli", "", "pass",
				"Couldn't remove weak moduli from your SSH daemon.  This is undesirable, as it weakens your security.  Please re-run the script to try and get this to work."));

		return units;
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws InvalidPortException, InvalidMachineModelException {
		final Collection<IUnit> units = new ArrayList<>();

		getMachineModel().addListen(Encapsulation.TCP, getServerModel().getSSHListenPort());

		return units;
	}

	@Override
	public Collection<IUnit> getLiveConfig() throws InvalidMachineException {
		final Collection<IUnit> units = new ArrayList<>();

		for (final UserModel admin : getServerModel().getAdmins()) {
			final String sshDir = admin.getHomeDirectory() + "/.ssh";
			final String keys = sshDir + "/authorized_keys";

			// Create the .ssh dir for the user, with the correct permissions
			units.add(new DirUnit("ssh_dir_" + admin, "sshd_config", sshDir));

			// Create the authorized_keys file, with root permissions (we don't want users
			// to be able to add arbitrary keys)
			final FileUnit authorised = new FileUnit("ssh_key_" + admin, "ssh_dir_" + admin + "_created", keys,
					"I couldn't add SSH keys for " + admin + " on " + getServerModel().getLabel() + "."
							+ " This user will not be able to SSH into " + getServerModel().getLabel());
			units.add(authorised);

			admin.getSSHPublicKey().ifPresent(key -> authorised.appendLine(key));
		}

		units.add(new RunningUnit("sshd", "sshd", "sshd"));

		return units;
	}

}
