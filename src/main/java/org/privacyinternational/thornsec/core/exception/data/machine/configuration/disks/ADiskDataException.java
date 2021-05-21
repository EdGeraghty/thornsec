/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks;

import org.privacyinternational.thornsec.core.exception.data.ADataException;

import java.io.Serial;

public class ADiskDataException extends ADataException {
	@Serial
	private static final long serialVersionUID = -4978682429685931190L;

	public ADiskDataException(String message) {
		super(message);
	}
}
