package org.privacyinternational.thornsec.core.data.machine.configuration;

import org.privacyinternational.thornsec.core.StringUtils;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPropertyException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.ADiskDataException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.InvalidDiskSizeException;

import javax.json.JsonObject;
import java.io.File;
import java.nio.file.Path;
import java.util.Optional;

public class HardDiskData extends DiskData {
    private Integer size;
    private File diffParent;
    private String comment;

    public HardDiskData(String label, Path filePath, JsonObject data) throws ADataException {
        super(label, filePath, data);
    }

    @Override
    public HardDiskData read(JsonObject data) throws ADiskDataException {
        super.read(data);

        if (data.containsKey("size")) {
            String size = data.getString("size");
            int sizeInMb = 0;
            try {
                sizeInMb = StringUtils.stringToMegaBytes(size);
            } catch (InvalidPropertyException e) {
                throw new InvalidDiskSizeException(size);
            }
            setSize(sizeInMb);
        }

        return this;
    }

    void setSize(int size) throws InvalidDiskSizeException {
        if (size < 512) {
            throw new InvalidDiskSizeException(size);
        }

        this.size = size;
    }

    void setComment(String comment) {
        this.comment = comment;
    }

    void setDiffParent(File diffParent) {
        this.diffParent = diffParent;
    }

    public Optional<Integer> getSize() {
        return Optional.ofNullable(this.size);
    }

    public Optional<File> getDiffParent() {
        return Optional.ofNullable(this.diffParent);
    }

    public Optional<String> getComment() {
        return Optional.ofNullable(this.comment);
    }
}