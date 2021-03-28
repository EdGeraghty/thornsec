/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data.machine.configuration;

import java.io.File;
import java.util.Optional;
import javax.json.JsonObject;

import org.privacyinternational.thornsec.core.data.AData;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.InvalidDiskSizeException;

/**
 * Represents some form of Disk attached to a Service
 */
public class DiskData extends AData {

	/**
	 * As far as we're concerned, there are only three file formats.
	 */
	public enum Format {
		VDI, VMDK, VHD, ISO;
	}

	private Format format;
	private File filename;

	public DiskData(String label) {
		super(label);

		this.format = null;
		this.filename = null;
	}

	public DiskData read(JsonObject data) throws InvalidDiskSizeException {
		if (data.containsKey("format")) {
			setFormat(Format.valueOf(data.getString("format").toUpperCase()));
		}
		if (data.containsKey("filename")) {
			setFilename(new File(data.getString("filename")));
		}

		return this;
	}

	private void setFilename(File filename) {
		this.filename = filename;
	}

	private void setFormat(Format format) {
		this.format = format;
	}

	public Optional<Format> getFormat() {
		return Optional.ofNullable(this.format);
	}

	public Optional<File> getFilename() {
		return Optional.ofNullable(this.filename);
	}

}
