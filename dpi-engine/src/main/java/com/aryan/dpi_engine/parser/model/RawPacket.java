package com.aryan.dpi_engine.parser.model;

public class RawPacket {
    public PcapPacketHeader header = new PcapPacketHeader();
    public byte[] data;  // The actual packet bytes
}
