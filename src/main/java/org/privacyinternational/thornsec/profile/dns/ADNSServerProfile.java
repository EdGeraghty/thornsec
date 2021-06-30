/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.dns;

import org.privacyinternational.thornsec.core.model.machine.AMachineModel;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.profile.AStructuredProfile;

import java.util.ArrayList;
import java.util.Collection;

/**
 * This is a DNS Server of some type.
 *
 * DNS Servers are quite involved, so you'll need to implement everything!
 */
public abstract class ADNSServerProfile extends AStructuredProfile {

	protected static final Integer DEFAULT_LISTEN_PORT = 53;

	public ADNSServerProfile(ServerModel me) {
		super(me);
	}

	/**
	 * Build DNS records for a given machine
	 */
	abstract Collection<String> createRecords(AMachineModel machine);

	/**
	 * Build DNS records for the whole network
	 */
	final Collection<String> createRecords(Collection<AMachineModel> machines) {
		Collection<String> records = new ArrayList<>();

		machines.forEach(machine -> records.addAll(createRecords(machine)));

		return records;
	}
}
