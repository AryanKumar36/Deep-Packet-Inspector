package com.aryan.dpi_engine.model;

public class PacketJob {
    public long packetId;
    public FiveTuple tuple = new FiveTuple();
    public byte[] data;
    public int ethOffset = 0;
    public int ipOffset = 0;
    public int transportOffset = 0;
    public int payloadOffset = 0;
    public int payloadLength = 0;
    public int tcpFlags = 0;

    // Timestamps
    public long tsSec;
    public long tsUsec;
}
