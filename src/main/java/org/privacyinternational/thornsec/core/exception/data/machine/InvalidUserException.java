/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.exception.data.machine;

public class InvalidUserException extends InvalidDeviceException {
	private static final long serialVersionUID = 2656177660603769643L;

	public InvalidUserException(String message) {
		super(message);
	}
}
