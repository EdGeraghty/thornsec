/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks;

public class InvalidDiskSizeException extends ADiskDataException {
	private static final long serialVersionUID = -8351165249687762249L;

	public InvalidDiskSizeException(String message) {
		super(message + " is an invalid disk size. The minimum value is 512m, but we recommend much bigger than that.");
	}

	public InvalidDiskSizeException(Integer size) {
		super(size + " is an invalid disk size. The minimum value is 512m, but we recommend much bigger than that.");
	}
}
