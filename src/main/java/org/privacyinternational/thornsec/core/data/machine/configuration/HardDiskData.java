package org.privacyinternational.thornsec.core.data.machine.configuration;

import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.InvalidDiskSizeException;

import java.io.File;
import java.util.Optional;

public class HardDiskData extends DiskData {
    private Integer size;
    private File diffParent;
    private String comment;

    public HardDiskData(String label) {
        super(label);

        this.size = null;
        this.diffParent = null;
        this.comment = null;
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