package com.aryan.dpi_engine.model;


public class RawPacket {
    private final byte[] data;
    private final long timestampSec;
    private final long timestampUsec;

    public RawPacket(byte[] data, long sec, long usec) {
        this.data = data;
        this.timestampSec = sec;
        this.timestampUsec = usec;
    }

    public byte[] getData() {
        return data;
    }

    public long getTimestampSec() {
        return timestampSec;
    }

    public long getTimestampUsec() {
        return timestampUsec;
    }

}
