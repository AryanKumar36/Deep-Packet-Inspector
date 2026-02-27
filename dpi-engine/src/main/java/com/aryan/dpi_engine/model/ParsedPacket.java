package com.aryan.dpi_engine.model;

public class ParsedPacket {

    // Metadata
    public long timestampSec;
    public long timestampUsec;

    // Ethernet
    public String srcMac;
    public String destMac;
    public int etherType;

    // IP
    public boolean hasIp;
    public int ipVersion;
    public int ttl;
    public int protocol;
    public String srcIp;
    public String destIp;

    // Transport
    public boolean hasTcp;
    public boolean hasUdp;
    public int srcPort;
    public int destPort;
    public long seqNumber;
    public long ackNumber;
    public byte tcpFlags;

    // Payload
    public int payloadLength;
    public byte[] payload;
}