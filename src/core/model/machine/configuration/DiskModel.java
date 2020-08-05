package core.model.machine.configuration;

import java.io.File;
import java.util.Optional;
import org.apache.commons.io.FilenameUtils;
import core.data.machine.configuration.DiskData;
import core.data.machine.configuration.DiskData.Format;
import core.data.machine.configuration.DiskData.Medium;
import core.exception.data.machine.InvalidDiskSizeException;
import core.model.AModel;
import core.model.network.NetworkModel;

public class DiskModel extends AModel {
	private Medium medium;
	private Format format;
	private File filename;
	private Integer size;
	private File diffParent;
	private String comment;

	public DiskModel(DiskData myData, NetworkModel networkModel) {
		super(myData, networkModel);
	}
	
	public DiskModel(String label, Medium medium, Format format, File filename, Integer size, File diffParent, String comment, NetworkModel networkModel) throws InvalidDiskSizeException {
		super(new DiskData(label), networkModel);
		this.setLabel(label);
		setMedium(medium);
		setFormat(format);
		setFilename(filename);
		setSize(size);
		setDiffParent(diffParent);
		setComment(comment);
	}
	
	/**
	 * @return the medium
	 */
	public Medium getMedium() {
		return medium;
	}

	/**
	 * @param medium the medium to set
	 */
	public void setMedium(Medium medium) {
		this.medium = medium;
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
		return FilenameUtils.normalize(filename.toString(), true);
	}
	
	public String getFilePath() {
		return FilenameUtils.normalize(filename.getParent().toString(), true);
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
	 */
	public void setSize(Integer size) {
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


}
