/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.iface;

/**
 * This interface represents a Unit Test.
 *
 * This is the fundamental building block on which ThornSec
 * is built.
 *
 * Each Unit Test should describe an expected state, the
 * steps required to get there, and how to know if everything
 * is OK.
 */
public interface IUnit  {

	/**
	 * @return the Unit Test's label
	 */
	String getLabel();

	/**
	 * @param quiet whether to output the current state and
	 *              expected state, or just pass/fail
	 * @return the bash script required to give a pass/fail
	 * on the current state v expected state
	 */
	String genAudit(boolean quiet);

	/**
	 * @return the bash script required to set the state to
	 * the one expected
	 */
	String genConfig();

	/**
	 * @return the bash script to run a "dry run" against the
	 * current state
	 */
	String genDryRun();

}
