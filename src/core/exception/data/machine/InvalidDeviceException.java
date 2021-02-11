/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package core.exception.data.machine;

public class InvalidDeviceException extends InvalidMachineException {
	private static final long serialVersionUID = 2656177660603769643L;

	public InvalidDeviceException(String message) {
		super(message);
	}
}
