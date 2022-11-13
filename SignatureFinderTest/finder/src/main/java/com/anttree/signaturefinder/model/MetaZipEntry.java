package com.anttree.signaturefinder.model;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class MetaZipEntry implements Comparable<MetaZipEntry> {
    private final String name;
    private final byte[] content;

    public MetaZipEntry(@NonNull String name, @Nullable byte[] content) {
        this.name = name;
        this.content = content;
    }

    @Override
    public int compareTo(MetaZipEntry o) {
        return this.name.compareTo(o.name);
    }

    //Get name of MetaZipEntry
    public String getName() {
        return name;
    }

    //Get content of MetaZipEntry
    public byte[] getContent() {
        return content;
    }
}