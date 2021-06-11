/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.exec.network;

import de.slackspace.openkeepass.KeePassDatabase;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;

import java.util.Collection;

public final class OpenKeePassPassphrase extends APassphrase {

	private KeePassDatabase db;

	public OpenKeePassPassphrase(ServerModel me) {
		super(me);

		this.db = null;
	}

	@Override
	public Boolean init() {
		//try {
			//final File keypassDB = new File(getNetworkModel().getKeePassDBPath(getMachineModel().getLabel()));
		//	if (keypassDB.isFile()) {
//				this.db = KeePassDatabase.getInstance(keypassDB);
//				this.db.openDatabase("IAmAString");
//
//				return true;
//			}
//		} catch (final URISyntaxException | IllegalArgumentException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}

		return false;
	}

	@Override
	public String getPassphrase() {
		// this.db.;
		return null;
	}

	@Override
	protected String generatePassphrase() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<IUnit> getUnits() throws AThornSecException {
		// TODO Auto-generated method stub
		return null;
	}
}
