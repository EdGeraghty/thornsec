/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data.machine;


import org.privacyinternational.thornsec.core.data.machine.configuration.DiskData;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPropertyException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.InvalidDiskSizeException;
import org.privacyinternational.thornsec.type.Hypervisor;

import javax.json.JsonObject;
import javax.json.JsonValue;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * This Class represents the data of a Service For our purposes, this is
 * something which runs on a {@link Hypervisor} - i.e. a Virtual Machine
 */
public class ServiceData extends ServerData {
	private ServerData hypervisor;

	private Map<String, DiskData> disks;

	private Integer backupFrequency;
	private Integer cpuExecutionCap;

	public ServiceData(String label, Path filePath, JsonObject data) throws ADataException {
		super(label, filePath, data);
	}

	@Override
	public ServiceData read(JsonObject data) throws ADataException {
		super.read(data);

		readDisks(data);
		readBackupFrequency(data);
		readCPUExecutionCap(data);

		return this;
	}

	private void readBackupFrequency(JsonObject data) throws InvalidPropertyException {
		if (!data.containsKey("backup_frequency")) {
			return;
		}
		
		setBackupFrequency(data.getInt("backup_frequency"));
	}

	/**
	 * Set the frequency with which to back up this machine, in whole hours
	 * 
	 * @param frequency in hours
	 * @throws InvalidPropertyException if <1
	 */
	private void setBackupFrequency(Integer frequency) throws InvalidPropertyException {
		if (frequency < 1) {
			throw new InvalidPropertyException("You must set backups a minimum of 1 hour apart");
		}
		
		this.backupFrequency = frequency;
	}

	/**
	 * Read in the CPU execution cap absolute percentage for this service
	 * 
	 * @throws InvalidPropertyException if the percentage is invalid
	 */
	private void readCPUExecutionCap(JsonObject data) throws InvalidPropertyException {
		if (!data.containsKey("cpu_execution_cap")) {
			return;
		}
		
		setCPUExecutionCap(data.getInt("cpu_execution_cap"));
	}

	/**
	 * Read in any disk information
	 * 
	 * @throws InvalidDiskSizeException if a disk size is invalid; this could
	 * 		potentially mean it's too small, or is NaN. 
	 */
	private void readDisks(JsonObject data) throws ADataException {
		if (!data.containsKey("disks")) {
			return;
		}
		final JsonObject disks = data.getJsonObject("disks");

		for (final Map.Entry<String, JsonValue> disk: disks.entrySet()) {
			this.addDisk(new DiskData(disk.getKey(), getFilePath(), disk.getValue().asJsonObject()));
		}
	}

	/**
	 * Add a disk derived from our JSON to this Service
	 * 
	 * @param diskData the disk to add
	 */
	private void addDisk(DiskData diskData) {
		if (this.disks == null) {
			this.disks = new LinkedHashMap<>();
		}
		
		this.disks.put(diskData.getLabel(), diskData);
	}

	/**
	 * Indicate we want to cap available CPU usage for this machine at a given percentage
	 * 
	 * @param capPct the cap, as an absolute percentage of CPU usage
	 * @throws InvalidPropertyException if the percentage is <1% or >100%
	 */
	protected void setCPUExecutionCap(Integer capPct) throws InvalidPropertyException {
		if (capPct < 1 || capPct > 100) {
			throw new InvalidPropertyException("CPU Execution Cap must be an integer between 1-100");
		}
		
		this.cpuExecutionCap = capPct;
	}

	/**
	 * Get all of the disks associated with this Service
	 * 
	 * @return a Map<label, DiskData> of all disks
	 */
	public final Optional<Map<String, DiskData>> getDisks() {
		return Optional.ofNullable(this.disks);
	}

	/**
	 * @return the backup frequency, in hours
	 */
	public final Optional<Integer> getBackupFrequency() {
		return Optional.ofNullable(this.backupFrequency);
	}

	/**
	 * @return the {@code label} of this service's HyperVisor
	 */
	public final ServerData getHypervisor() {
		return this.hypervisor;
	}

	/**
	 * Set the Hypervisor for this machine - warning, this is unchecked. You're
	 * expected to make sure this machine exists elsewhere.
	 *
	 * @param hv The label of the hypervisor machine
	 */
	public final void setHypervisor(ServerData hv) {
		this.hypervisor = hv;
	}
	
	/**
	 * @return The CPU execution cap as an absolute percentage {1-100}
	 */
	public Optional<Integer> getCPUExecutionCap() {
		return Optional.ofNullable(this.cpuExecutionCap);
	}

}
