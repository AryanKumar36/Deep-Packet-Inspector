package com.aryan.dpi_engine.parser.model;

public class PcapGlobalHeader {
    public long magicNumber;    // 0xa1b2c3d4 (or swapped for big-endian)
    public int versionMajor;    // Usually 2
    public int versionMinor;    // Usually 4
    public int thiszone;        // GMT offset (usually 0)
    public long sigfigs;        // Accuracy of timestamps (usually 0)
    public long snaplen;        // Max length of captured packets
    public long network;        // Data link type (1 = Ethernet)
}
