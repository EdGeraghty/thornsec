/*
 * This code is part of the ThornSec project.
 * 
 * To learn more, please head to its GitHub repo: @privacyint
 * 
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core;

import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.model.network.ThornsecModel;
import org.privacyinternational.thornsec.core.view.FullFrame;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;

public class Main {

	/**
	 * The main method.
	 *
	 * @param args [0] - Path to our JSON
	 */
	public static void main(String[] args) throws AThornSecException {
		String jsonPath = null;

		if (args.length == 0) {
			final JFileChooser chooser = new JFileChooser();
			final FileNameExtensionFilter filter = new FileNameExtensionFilter("JSON Config File", "json");
			chooser.setFileFilter(filter);
			final int returnVal = chooser.showOpenDialog(null);

			if (returnVal == JFileChooser.APPROVE_OPTION) {
				jsonPath = chooser.getSelectedFile().getPath();
			}
		} else {
			jsonPath = args[0];
		}

		final ThornsecModel model = new ThornsecModel();

		try {
			model.read(jsonPath);

			new FullFrame(model);
		}
		catch (Exception e) {
			JOptionPane.showMessageDialog(null, e);
		}
	}

}
