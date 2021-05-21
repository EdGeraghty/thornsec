/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine.configuration.disks;

import java.io.File;
import java.util.Optional;
import org.privacyinternational.thornsec.core.data.machine.configuration.DiskData;
import org.privacyinternational.thornsec.core.data.machine.configuration.DiskData.Format;
import org.privacyinternational.thornsec.core.data.machine.configuration.HardDiskData;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.DiskModelException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.ADiskDataException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.InvalidDiskSizeException;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;

public class HardDiskModel extends ADiskModel {
	private Format format;
	private Integer size;
	private File diffParent;
	private String comment;

	public HardDiskModel(HardDiskData myData, NetworkModel networkModel) throws ADiskDataException {
		super(myData, networkModel);

		setFormat(myData.getFormat().orElseGet(() -> null));
		setFilename(myData.getFilename().orElseGet(() -> null));
		setSize(myData.getSize().orElseGet(() -> null));
		setDiffParent(myData.getDiffParent().orElseGet(() -> null));
		setComment(myData.getComment().orElseGet(() -> null));
	}

	public HardDiskModel(String label, File filename) {
		super(new DiskData(label, null, Json.createObjectBuilder().build()), null);
		
		setFilename(filename);
	}

	/**
	 * @return the disk format
	 */
	public Format getFormat() {
		return format;
	}

	/**
	 * @param format the format to set. If `null`, defaults to VMDK
	 */
	public void setFormat(Format format) {
		if (null == format) {
			format = Format.VMDK;
		}

		this.format = format;
	}

	/**
	 * @return the size
	 */
	public Integer getSize() {
		return size;
	}

	/**
	 * @param size the disk's size
	 * @throws InvalidDiskSizeException if < 8192 (8GB)
	 */
	public void setSize(Integer size) throws InvalidDiskSizeException {
		if (null == size) {
			size = 20480;
		}

		if (size < 8192) {
			throw new InvalidDiskSizeException(size);
		}

		this.size = size;
	}

	/**
	 * @return the diffParent
	 */
	public Optional<File> getDiffParent() {
		return Optional.ofNullable(diffParent);
	}

	/**
	 * @param diffParent the diffParent to set
	 */
	public void setDiffParent(File diffParent) {
		//diffParent's allowed to be null.
		this.diffParent = diffParent;
	}

	/**
	 * @return the comment
	 */
	public Optional<String> getComment() {
		return Optional.ofNullable(comment);
	}

	/**
	 * @param comment the comment to set
	 */
	public void setComment(String comment) {
		//Comment's allowed to be null
		this.comment = comment;
	}
}
