/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.machine.configuration;

import java.io.File;
import java.nio.file.Path;
import java.util.*;

import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.profile.AProfile;

public class FileSystem extends AProfile {

	private final Map<Path, String> files;

	public FileSystem(ServerModel me) {
		super(me);

		this.files = new HashMap<>();
	}

	public void addFile(String path) {
		//this.files.add(new File(path));
	}

	@Override
	public Collection<IUnit> getUnits() {
		return null;
	}
}
