/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine.configuration.disks;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;
import org.apache.commons.io.FilenameUtils;
import org.privacyinternational.thornsec.core.data.machine.configuration.DiskData;
import org.privacyinternational.thornsec.core.data.machine.configuration.DiskData.Format;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.InvalidDiskSizeException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.AModel;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;

public class ADiskModel extends AModel {
	private Format format;
	private File filename;
	private Integer size;
	private File diffParent;
	private String comment;

	public ADiskModel(DiskData myData, NetworkModel networkModel) {
		super(myData);
		getData().getFilename().ifPresent(this::setFilename);
		getData().getFormat().ifPresent(this::setFormat);
	}

	/**
	 * @return the format
	 */
	public Format getFormat() {
		return format;
	}

	/**
	 * @param format the format to set
	 */
	public void setFormat(Format format) {
		this.format = format;
	}

	/**
	 * @return the filename
	 */
	public String getFilename() {
		if (null == this.filename) {
			return null;
		}
	
		return FilenameUtils.normalize(this.filename.toString(), true);
	}

	public String getFilePath() {
		if (null == this.filename) {
			return null;
		}

		return FilenameUtils.normalize(this.filename.getParent().toString(), true);
	}

	/**
	 * @param filename the filename to set
	 */
	public void setFilename(File filename) {
		this.filename = filename;
	}

	/**
	 * @return the size
	 */
	public Integer getSize() {
		return size;
	}

	/**
	 * @param size the size to set
	 * @throws InvalidDiskSizeException 
	 */
	public void setSize(Integer size) throws InvalidDiskSizeException {
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
		this.comment = comment;
	}

	@Override
	public Collection<IUnit> getUnits() throws AThornSecException {
		return new ArrayList<>();
	}

	@Override
	public DiskData getData() {
		return (DiskData) super.getData();
	}
}
