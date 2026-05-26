package com.aryan.dpi_engine.parser.model;


public class ParsedPacket {
    // Timestamps
    public long timestampSec;
    public long timestampUsec;

    // Ethernet layer
    public String srcMac = "";
    public String destMac = "";
    public int etherType;

    // IP layer (if present)
    public boolean hasIp = false;
    public int ipVersion;
    public String srcIp = "";
    public String destIp = "";
    public int protocol;       // TCP=6, UDP=17, ICMP=1
    public int ttl;

    // Transport layer (if present)
    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int srcPort;
    public int destPort;

    // TCP-specific
    public int tcpFlags;
    public long seqNumber;
    public long ackNumber;

    // Payload
    public int payloadLength;
    public int payloadOffset = -1;  // offset into original packet data
}
