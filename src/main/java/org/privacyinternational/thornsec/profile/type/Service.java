/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.type;

import java.util.ArrayList;
import java.util.Collection;
import org.privacyinternational.thornsec.core.data.machine.AMachineData.MachineType;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidMachineModelException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.model.machine.ServiceModel;
import org.privacyinternational.thornsec.core.unit.SimpleUnit;
import org.privacyinternational.thornsec.core.unit.fs.DirMountedUnit;
import org.privacyinternational.thornsec.core.unit.fs.DirUnit;
import org.privacyinternational.thornsec.core.unit.fs.FileAppendUnit;
import org.privacyinternational.thornsec.profile.guest.AOS;
import org.privacyinternational.thornsec.profile.guest.Alpine;

/**
 * This is a Service, which represents a VM on a HyperVisor
 */
public class Service extends Server {

	public Service(ServerModel me) {
		super(me);
	}

	public final Hypervisor getHypervisor() throws InvalidMachineModelException {
		String label = getServerModel().getHypervisorLabel();
		return (Hypervisor) getNetworkModel()
								.getMachineModel(label)
								.getType(MachineType.HYPERVISOR);
	}

	public final AOS getGuestProfile() throws AThornSecException {
		//return getServerModel().get;
		return new Alpine(getServerModel());
	}

	@Override
	public Collection<IUnit> getPersistentConfig() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		// Mount /media/backup
		units.add(new FileAppendUnit("backup_fstab", "is_virtualbox_guest", "backup    /media/backup      vboxsf defaults,_netdev,ro 0 0", "/etc/fstab",
				"Couldn't create the mount for the backup at /media/backup.  Meh."));
		units.add(new DirUnit("backup_bindpoint", "is_virtualbox_guest", "/media/backup"));
		units.add(new DirMountedUnit("backup", "backup_fstab_appended", "backup", "Couldn't mount the backup directory."));

		// Mount /var
		units.add(new FileAppendUnit("log_fstab", "is_virtualbox_guest", "log       /var/log           vboxsf defaults,dmode=751,_netdev 0 0", "/etc/fstab",
				"Couldn't create the mount for /var/log.  Meh."));
		units.add(new SimpleUnit("log_mounted", "log_fstab_appended", "sudo mkdir /tmp/log;" + "sudo mv /var/log/* /tmp/log;" + "sudo mount log;" + "sudo mv /tmp/log/* /var/log;",
				"mount | grep 'log on /var/log' 2>&1", "", "fail",
				"Couldn't move & remount the logs.  This is usually caused by logs already being in the hypervisor, on the first config of a service.  This can be fixed by rebooting the service (though you will lose any logs from the installation)"));

		units.addAll(super.getPersistentConfig());

		return units;
	}

	@Override
	public ServiceModel getServerModel() {
		return (ServiceModel) getServerModel();
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.addAll(super.getPersistentFirewall());
//		//getMachineModel().addEgress("download.virtualbox.org");

		return units;
	}
}
