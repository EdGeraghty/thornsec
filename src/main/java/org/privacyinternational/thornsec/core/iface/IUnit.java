package org.privacyinternational.thornsec.core.iface;

public interface IUnit  {
	
	String getLabel();

	String genAudit(boolean quiet);

	String genConfig();

	String genDryRun();

}