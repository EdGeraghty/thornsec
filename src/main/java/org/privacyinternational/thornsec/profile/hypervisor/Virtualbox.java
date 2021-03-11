/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.hypervisor;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPortException;
import org.privacyinternational.thornsec.core.exception.data.NoValidUsersException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidServerException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidMachineModelException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidServerModelException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.HypervisorModel;
import org.privacyinternational.thornsec.core.model.machine.ServiceModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.disks.DVDModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.disks.HardDiskModel;
import org.privacyinternational.thornsec.core.unit.SimpleUnit;
import org.privacyinternational.thornsec.core.unit.fs.DirUnit;
import org.privacyinternational.thornsec.core.unit.fs.FileUnit;
import org.privacyinternational.thornsec.core.unit.pkg.InstalledUnit;
import inet.ipaddr.HostName;

public class Virtualbox extends AHypervisorProfile {
	final static String USER_PREFIX = "vboxuser_";
	final static String GROUP = "vboxusers";

	public Virtualbox(HypervisorModel me) {
		super(me);
	}

	/**
	 * Build and attach all disks relating to a given service
	 *
	 * @param service the service to build the disks for
	 * @return units to build & attach disks to our service
	 */
	@Override
	protected Collection<IUnit> buildDisks(ServiceModel service) {
		final Collection<IUnit> units = new ArrayList<>();

		Set<HardDiskModel> hdds = service.getDisks()
										 .values()
										 .stream()
										 .filter(disk -> disk.getMedium() == Medium.DISK)
										 .map(HardDiskModel.class::cast)
										 .collect(Collectors.toSet());

		Set<DVDModel> dvds = service.getDisks()
									.values()
									.stream()
									.filter(disk -> disk.getMedium() == Medium.DVD)
									.map(DVDModel.class::cast)
									.collect(Collectors.toSet());

		units.addAll(buildHDDController(service, hdds));
		units.addAll(buildDVDController(service, dvds));
		units.addAll(buildHDDs(service, hdds));
		units.addAll(buildDVDs(service, dvds));
		units.addAll(bootOrder(service));

		return units;
	}

	/**
	 * Builds the HDD Controller, ready for attaching disks
	 * @param service Service to build our disks for
	 * @param hdds disks to build
	 * @return IUnits to create the HDD Controller on our Service
	 */
	private Collection<IUnit> buildHDDController(ServiceModel service, Set<HardDiskModel> hdds) {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new SimpleUnit(service.getLabel() + "_hdds_sas_controller",
					service.getLabel() + "_exists",
					"sudo -u " + USER_PREFIX + service.getLabel()
						+ " VBoxManage"
							+ " storagectl " + service.getLabel()
							+ " --name \"HDDs\""
							+ " --add sas"
							+ " --controller LSILogicSAS"
							+ " --portcount " + hdds.size()
							+ " --hostiocache off",
					"sudo -u " + USER_PREFIX + service.getLabel()
						+ " VBoxManage"
							+ " showvminfo " + service.getLabel()
							+ " --machinereadable"
						+ " | grep ^storagecontrollername0=",
				"storagecontrollername0=\\\"HDDs\\\"",
				"pass",
				"The hard drive SAS controller for " + service.getLabel()
					+ " (where its disks are attached) couldn't be created/attached"
					+ " to " + service.getLabel() + ". "
					+ "This is fatal, " + service.getLabel() + " will not be installed.")
		);

		return units;
	}

	/**
	 * Builds the DVD Controller, ready for attaching disks
	 * @param service
	 * @param dvds
	 * @return
	 */
	private Collection<IUnit> buildDVDController(ServiceModel service, Set<DVDModel> dvds) {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new SimpleUnit(service.getLabel() + "_dvds_ide_controller",
				service.getLabel() + "_exists",
				"sudo -u " + USER_PREFIX + service.getLabel()
					+ " VBoxManage"
						+ " storagectl " + service.getLabel()
						+ " --name \"DVDs\""
						+ " --add ide"
						+ " --controller PIIX4"
						+ " --hostiocache off",
				"sudo -u " + USER_PREFIX + service.getLabel()
					+ " VBoxManage"
						+ " showvminfo " + service.getLabel()
						+ " --machinereadable"
				+ " | grep ^storagecontrollername1=",
				"storagecontrollername1=\\\"DVDs\\\"",
				"pass",
				"The DVD IDE controller for " + service.getLabel()
						+ " (where its disks are attached) couldn't be created/attached"
						+ " to " + service.getLabel() + ". "
						+"This is fatal, " + service.getLabel() + " will not be installed.")
		);

		return units;
	}

	private Collection<IUnit> buildHDDs(ServiceModel service, Set<HardDiskModel> hdds) {
		final Collection<IUnit> units = new ArrayList<>();

		int deviceCounter = 0;
		for (final HardDiskModel disk : hdds) {
			units.add(
				new DirUnit(
					disk.getLabel() + "_disk_dir_" + service.getLabel(),
					"proceed",
					disk.getFilePath(),
					USER_PREFIX + service.getLabel(),
					GROUP,
					0750,
					""
				)
			);

			units.add(
				new DirUnit(
					disk.getLabel() + "_disk_loopback_dir_" + service.getLabel(),
					"proceed",
					disk.getFilePath() + "/live/",
					"root",
					"root",
					700,
					""
				)
			);

			String diskCreation = "";
			diskCreation += "sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage createmedium --filename " + disk.getFilename();
			diskCreation += " --size " + disk.getSize();
			diskCreation += " --format " + disk.getFormat();
			diskCreation += (disk.getDiffParent().isPresent()) ? " --diffparent " + disk.getDiffParent() : "";

			units.add(new SimpleUnit(service.getLabel() + "_" + disk.getLabel() + "_disk",
					disk.getLabel() + "_disk_dir_" + service.getLabel() + "_chmoded", diskCreation,
					"sudo [ -f " + disk.getFilename() + " ] && echo pass;", "pass", "pass",
					"Couldn't create the disk " + disk.getLabel() + " for " + service.getLabel() + "."));
//			units.add(new FileOwnUnit(service.getLabel() + "_" + disk.getLabel() + "_disk",
//					service.getLabel() + "_" + disk.getLabel() + "_disk", disk.getFilename(), user, group));

			String diskAttach = "";
			diskAttach += "sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage storageattach " + service;
			diskAttach += " --storagectl \"HDDs\"";
			diskAttach += " --port " + deviceCounter;
			diskAttach += " --device 0";
			diskAttach += " --type hdd";
			diskAttach += " --medium " + disk.getFilename();
			// diskAttach += (disk.getLabel().contentEquals("boot")) ? " --bootable on" : "
			// --bootable -off";
			// diskAttach += " --comment \\\"" + disk.getComment() + "\\\";";

			units.add(new SimpleUnit(service.getLabel() + "_" + disk.getLabel() + "_disk_attached",
					service.getLabel() + "_hdds_sas_controller", diskAttach,
					"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage showvminfo " + service.getLabel() + " --machinereadable | grep \"HDDs-"
							+ deviceCounter + "-0\"",
					"\\\"HDDs-" + deviceCounter + "-0\\\"=\\\"" + disk.getFilename() + "\\\"", "pass",
					"Couldn't attach disk " + disk.getLabel() + "for " + service.getLabel() + "."));

			deviceCounter++;
		}

		return units;
	}

	private Collection<IUnit> buildDVDs(ServiceModel service, Set<DVDModel> dvds) {
		final Collection<IUnit> units = new ArrayList<>();

		int deviceCounter = 0;
		for (DVDModel dvd : dvds) {
			String diskAttach = "";
			diskAttach += "sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage storageattach " + service;
			diskAttach += " --storagectl \"DVDs\"";
			diskAttach += " --port " + deviceCounter;
			diskAttach += " --device 0";
			diskAttach += " --type dvddrive";
			diskAttach += " --medium " + dvd.getFilename();
			// diskAttach += (disk.getLabel().contentEquals("boot")) ? " --bootable on" : "
			// --bootable -off";
			// diskAttach += " --comment \\\"" + disk.getComment() + "\\\";";

			units.add(new SimpleUnit(service.getLabel() + "_" + dvd.getLabel() + "_disk_attached",
					service.getLabel() + "_dvds_ide_controller", diskAttach,
					"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage showvminfo " + service.getLabel() + " --machinereadable | grep \"DVDs-0-"
							+ deviceCounter + "\"",
					"\\\"DVDs-" + deviceCounter + "-0\\\"=\\\"" + dvd.getFilename() + "\\\"", "pass",
					"Couldn't attach disk " + dvd.getLabel() + " for " + service.getLabel() + "."));

			deviceCounter++;
		}

		return units;
	}

	private Collection<IUnit> bootOrder(ServiceModel service) {
		final Collection<IUnit> units = new ArrayList<>();

		// Boot setup - DVD is second to stop machines being wiped every time they're
		// brought up
		units.add(
			modifyVm(
				service,
				"boot1",
				"disk",
				"Couldn't set the boot order for " + service.getLabel() + ". "
					+ " This may mean the service will not be installed.",
				service.getLabel() + "_hdds_sas_controller"
			)
		);

		units.add(
			modifyVm(
				service,
				"boot2",
				"dvd",
				"Couldn't set the boot order for " + service.getLabel() + ". "
					+ " This may mean the service will not be installed.",
				service.getLabel() + "_dvds_ide_controller"
			)
		);

		return units;
	}

	/**
	 * Build and attach backup directory to a given service
	 *
	 * @param service the service to attach to
	 * @return units to build & attach backup directories
	 */
	@Override
	protected Collection<IUnit> buildBackups(ServiceModel service) {
		final Collection<IUnit> units = new ArrayList<>();

		final String baseDir = getServerModel().getVMBase().getAbsolutePath();
		final String backupDir = baseDir + "/backups/" + service.getLabel();

		units.add(
			new DirUnit(
				"backup_dir_" + service.getLabel(),
				"proceed",
				backupDir,
				USER_PREFIX + service.getLabel(),
				GROUP,
				0750,
				""
			)
		);

		// Mark the backup destination directory as a valid destination
		units.add(
			new FileUnit(
				service.getLabel() + "_mark_backup_dir",
				"backup_dir_" + service.getLabel() + "_chmoded",
				backupDir + "/backup.marker",
				"In memoriam Luke and Guy.  Miss you two!"
			)
		);

		units.add(
			new SimpleUnit(
				service.getLabel() + "_backup_sf_attached",
				service.getLabel() + "_exists",
				"sudo -u " + USER_PREFIX + service.getLabel()
					+ " VBoxManage"
						+ " sharedfolder add " + service.getLabel()
						+ " --name backup"
						+ " --hostpath "
						+ backupDir,
				"sudo -u " + USER_PREFIX + service.getLabel()
					+ " VBoxManage"
						+ " showvminfo " + service.getLabel()
						+ " --machinereadable"
				+ " | grep " + backupDir,
				"",
				"fail"
			)
		);

		return units;
	}

	/**
	 * Build and attach logs directory to a given service
	 *
	 * @param service the service to attach to
	 * @return units to build & attach logs directory
	 */
	@Override
	protected Collection<IUnit> buildLogs(ServiceModel service) {
		final Collection<IUnit> units = new ArrayList<>();

		final String baseDir = getServerModel().getVMBase().getAbsolutePath();
		final String logDir = baseDir + "/logs/" + service.getLabel();

		units.add(
			new DirUnit(
				"log_dir_" + service.getLabel(),
				"proceed",
				logDir,
				USER_PREFIX + service.getLabel(),
				GROUP,
				0750,
				""
			)
		);

		units.add(
			new SimpleUnit(
				service.getLabel() + "_log_sf_attached",
				service.getLabel() + "_exists",
				"sudo -u " + USER_PREFIX + service.getLabel()
					+ " VBoxManage"
						+ " sharedfolder add " + service.getLabel()
						+ " --name logs"
						+ " --hostpath " + logDir
				+ ";"
				+ "sudo -u " + USER_PREFIX + service.getLabel()
					+ " VBoxManage"
						+ " setextradata " + service.getLabel()
						+ " VBoxInternal1/SharedFoldersEnableSymlinksCreate/logs 1",
				"sudo -u " + USER_PREFIX + service.getLabel()
					+ " VBoxManage"
						+ " showvminfo " + service.getLabel()
						+ " --machinereadable"
				+ " | grep " + logDir,
				"",
				"fail",
				"Couldn't attach the logs folder to " + service.getLabel() + "."
				+ "This means logs will only exist in the VM."
			)
		);

		return units;
	}

	private IUnit createVMUser(ServiceModel service) {
		return new SimpleUnit(
			service.getHypervisorLabel() + "_virtualbox_" + service.getLabel() + "_user",
			"virtualbox_installed",
			"sudo adduser " + USER_PREFIX + service.getLabel()
				+ " --system" //create with no aging information in /etc/shadow
				+ " --shell=/bin/false" //force no login shell
				+ " --disabled-login" //deactivate ability to log in as account
				+ " --ingroup " + GROUP,
			"id -u " + USER_PREFIX + service.getLabel() + " 2>&1"
			+ " | grep 'no such user'",
			"",
			"pass",
			"Couldn't create the user for " + service.getLabel()
				+ " on its HyperVisor.  This is fatal, "
				+ service.getLabel() + " will not be installed.");
	}

	private final IUnit createVM(ServiceModel service) {
		return new SimpleUnit(service.getLabel() + "_exists", service.getHypervisorLabel() + "_virtualbox_" + service.getLabel() + "_user",
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage createvm"
						+ "--name " + service.getLabel()
						+ " --ostype \"" + GROUP + "\""
						+ " --register;"
						+ "sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage modifyvm " + service.getLabel()
						+ " --description \"" + service.getLabel() + "." + service.getDomain() + "\n"
						+ "ThornSec guest machine\n"
						+ "Built with profile(s): "	+ String.join(", ", service.getProfiles().keySet()) + "\n"
						+ "Built at $(date)" + "\"",
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage list vms | grep " + service.getLabel(), "", "fail", "Couldn't create " + service.getLabel()
						+ " on its HyperVisor.  This is fatal, " + service.getLabel() + " will not exist on your network.");
	}

	private final Collection<IUnit> createSockets(ServiceModel service) {
		final Collection<IUnit> units = new ArrayList<>();
		final String ttySocketDir = getServerModel().getVMBase().getPath() + "/sockets/" + service.getLabel();

		units.add(new DirUnit("socket_dir_" + service.getLabel(), "proceed", ttySocketDir, USER_PREFIX + service.getLabel(), GROUP, 0750, ""));
		// tty0 socket
		units.add(new SimpleUnit(service.getLabel() + "_tty0_com_port", service.getLabel() + "_exists",
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage modifyvm " + service.getLabel() + " --uart1 0x3F8 4",
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage showvminfo " + service.getLabel() + " --machinereadable | grep ^uart1=",
				"uart1=\\\"0x03f8,4\\\"", "pass"));

		units.add(new SimpleUnit(service.getLabel() + "_tty0_socket", service.getLabel() + "_tty0_com_port",
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage modifyvm " + service.getLabel() + " --uartmode1 server " + ttySocketDir
						+ "/vboxttyS0",
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage showvminfo " + service.getLabel() + " --machinereadable | grep ^uartmode1=",
				"uartmode1=\\\"server," + ttySocketDir + "/vboxttyS0\\\"", "pass"));

		units.add(new SimpleUnit(service.getLabel() + "_tty1_com_port", service.getLabel() + "_exists",
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage modifyvm " + service.getLabel() + " --uart2 0x2F8 3",
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage showvminfo " + service.getLabel() + " --machinereadable | grep ^uart2=",
				"uart2=\\\"0x02f8,3\\\"", "pass"));

		units.add(new SimpleUnit(service.getLabel() + "_tty1_socket", service.getLabel() + "_tty1_com_port",
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage modifyvm " + service.getLabel() + " --uartmode2 server " + ttySocketDir
						+ "/vboxttyS1",
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage showvminfo " + service.getLabel() + " --machinereadable | grep ^uartmode2=",
				"uartmode2=\\\"server," + ttySocketDir + "/vboxttyS1\\\"", "pass"));

		return units;
	}

	@Override
	public Collection<IUnit> buildVM(ServiceModel service) {
		final String baseDir = getServerModel().getVMBase().getAbsolutePath();

		final String ttySocketDir = baseDir + "/sockets/" + service.getLabel();

		final Collection<IUnit> units = new ArrayList<>();

		units.add(createVMUser(service));
		units.add(createVM(service));
		units.addAll(createSockets(service));

		// Architecture setup
		units.add(modifyVm(service, "paravirtprovider", "kvm")); // Default, make it explicit
		units.add(modifyVm(service, "chipset", "ich9"));
		units.add(modifyVm(service, "ioapic", "on",
				"IO APIC couldn't be enabled for " + service.getLabel()
				+ ".  This is required for 64-bit installations, and for more than 1 virtual CPU in a service."));
		units.add(modifyVm(service, "hwvirtex", "on"));
		units.add(modifyVm(service, "pae", "on"));
		units.add(modifyVm(service, "cpus", service.getCPUs()));
		units.add(modifyVm(service, "cpuexecutioncap", service.getCPUExecutionCap()));

		// RAM setup
		units.add(modifyVm(service, "memory", service.getRAM()));
		units.add(modifyVm(service, "vram", "16"));
		units.add(modifyVm(service, "nestedpaging", "on"));
		units.add(modifyVm(service, "largepages", "on"));

		// Audio setup (switch it off)
		units.add(modifyVm(service, "audio", "none"));

		// Use high precision event timers instead of legacy
		units.add(modifyVm(service, "hpet", "on"));

		// Shared folders setup
		units.add(new SimpleUnit(service.getLabel() + "_backup_sf_attached", service.getLabel() + "_exists",
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage sharedfolder add " + service.getLabel() + " --name backup --hostpath "
						+ backupDir,
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage showvminfo " + service.getLabel()
						+ " --machinereadable | grep SharedFolderPathMachineMapping2",
				"SharedFolderPathMachineMapping2=\\\"" + backupDir + "\\\"", "pass"));

		// Clock setup to try and stop drift between host and guest
		// https://www.virtualbox.org/manual/ch09.html#changetimesync
		units.add(guestPropertySet(service, "timesync-interval", "10000", "Couldn't sync the clock between "
				+ service.getLabel() + " and its metal.  You'll probably see some clock drift in " + service.getLabel() + " as a result."));
		units.add(guestPropertySet(service, "timesync-min-adjust", "100", "Couldn't sync the clock between "
				+ service.getLabel() + " and its metal.  You'll probably see some clock drift in " + service.getLabel() + " as a result."));
		units.add(guestPropertySet(service, "timesync-set-on-restore", "1", "Couldn't sync the clock between "
				+ service.getLabel() + " and its metal.  You'll probably see some clock drift in " + service.getLabel() + " as a result."));
		units.add(guestPropertySet(service, "timesync-set-threshold", "1000", "Couldn't sync the clock between "
				+ service.getLabel() + " and its metal.  You'll probably see some clock drift in " + service.getLabel() + " as a result."));


		getServerModel().addProcessString("/usr/lib/virtualbox/VBoxHeadless --comment " + service.getLabel() + " --startvm `if id '" + USER_PREFIX + service.getLabel()
						+ "' >/dev/null 2>&1; then sudo -u " + USER_PREFIX + service.getLabel() + " bash -c 'VBoxManage list runningvms | grep "
						+ service.getLabel() + "' | awk '{ print $2 }' | tr -d '{}'; else echo ''; fi` --vrde config *$");
		getServerModel().addProcessString("awk \\{");
		getServerModel().addProcessString("tr -d \\{\\}$");
		getServerModel().getUserModel().addUsername(USER_PREFIX + service.getLabel());

		return units;
	}

	@Override
	public Collection<IUnit> getInstalled() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new InstalledUnit("ca_certificates", "proceed", "ca-certificates"));
		units.add(new SimpleUnit("virtualbox_pgp", "proceed",
				"busybox wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O - | sudo apt-key add -",
				"apt-key list | grep virtualbox", "", "fail",
				"I couldn't import the PGP public key corresponding to"
				+ " the VirtualBox Debian repository. VirtualBox won't be installed."));

		FileUnit source = new FileUnit("virtualbox_repository", "virtualbox_pgp",
				"/etc/apt/sources.list.d/virtualbox.list",
				"");
		source.appendLine("deb http://download.virtualbox.org/virtualbox/debian bionic contrib");
		units.add(source);

		units.add(new InstalledUnit("metal_virtualbox", "virtualbox_repository", "virtualbox-6.1"));
		units.add(new InstalledUnit("metal_genisoimage", "proceed", "genisoimage"));
		units.add(new InstalledUnit("metal_rsync", "proceed", "rsync"));
		units.add(new InstalledUnit("metal_guestfs_utils", "proceed", "libguestfs-tools"));
		units.add(new InstalledUnit("metal_wget", "proceed", "wget"));

		return units;
	}

	@Override
	public final Collection<IUnit> getPersistentConfig() throws InvalidMachineModelException {
		final Collection<IUnit> units = new ArrayList<>();

		getServerModel().addProcessString("/usr/lib/virtualbox/VBoxXPCOMIPCD$");
		getServerModel().addProcessString("/usr/lib/virtualbox/VBoxSVC --auto-shutdown$");
		getServerModel().addProcessString("\\[iprt-VBoxWQueue\\]$");
		getServerModel().addProcessString("\\[iprt-VBoxTscThr\\]$");
		getServerModel().addProcessString("\\[kvm-irqfd-clean\\]$");

		return units;
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws InvalidMachineModelException, InvalidPortException {
		final Collection<IUnit> units = new ArrayList<>();

		//getServerModel().getAptSourcesModel().addAptSource("virtualbox", "deb http://download.virtualbox.org/virtualbox/debian buster contrib", "keyserver.ubuntu.com", "a2f683c52980aecf");
		getMachineModel().addEgress(new HostName("virtualbox.org:443"));
		getMachineModel().addEgress(new HostName("download.virtualbox.org:80"));

		return units;
	}

	protected SimpleUnit modifyVm(ServiceModel service, String setting, String value, String errorMsg, String prerequisite) {

		String check;

		// Integers aren't quoted...
		if (value.matches("-?(0|[1-9]\\d*)")) {
			check = setting + "=" + value;
		} else {
			check = setting + "=\\\"" + value + "\\\"";
		}

		return new SimpleUnit(
			service.getLabel() + "_" + setting + "_" + value,
			prerequisite,
			"sudo -u " + USER_PREFIX + service.getLabel()
				+ " VBoxManage"
					+ " modifyvm " + service.getLabel()
						+ " --" + setting + " " + value,
			"sudo -u " + USER_PREFIX + service.getLabel()
				+ " VBoxManage"
					+ " showvminfo " + service.getLabel()
						+ " --machinereadable"
			+ " | grep ^" + setting + "=",
			check,
			"pass",
			errorMsg
		);
	}

	protected SimpleUnit modifyVm(ServiceModel service, String setting, String value, String errorMsg) {
		return modifyVm(service, setting, value, errorMsg, service.getLabel() + "_exists");
	}

	protected SimpleUnit modifyVm(ServiceModel service, String setting, String value) {
		return modifyVm(service, setting, value, "Couldn't change " + setting + " to " + value);
	}

	protected SimpleUnit modifyVm(ServiceModel service, String setting, Integer value) {
		return modifyVm(service, setting, value + "", "Couldn't change " + setting + " to " + value);
	}

	protected SimpleUnit guestPropertySet(ServiceModel service, String property, String value, String errorMsg,
										  String prerequisite) {
		return new SimpleUnit(service.getLabel() + "_" + property.replaceAll("-", "_") + "_" + value, prerequisite,
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage guestproperty set " + service
						+ " \"/VirtualBox/GuestAdd/VBoxService/--" + property + "\" " + value,
				"sudo -u " + USER_PREFIX + service.getLabel() + " VBoxManage guestproperty enumerate " + service
						+ " | grep \"Name: /VirtualBox/GuestAdd/VBoxService/--" + property + ", value: " + value + "\"",
				"", "fail", errorMsg);
	}

	protected SimpleUnit guestPropertySet(ServiceModel service, String property, String value, String errorMsg) {
		return guestPropertySet(service, property, value, errorMsg, service.getLabel() + "_exists");
	}

	public Collection<? extends IUnit> buildIso(String service) throws InvalidServerException, InvalidServerModelException, NoValidUsersException, MalformedURLException, URISyntaxException, InvalidMachineModelException {
		// TODO Auto-generated method stub
		return null;
	}

}
