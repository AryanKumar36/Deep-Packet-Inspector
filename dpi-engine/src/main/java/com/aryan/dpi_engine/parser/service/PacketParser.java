package com.aryan.dpi_engine.parser.service;

import com.aryan.dpi_engine.parser.model.ParsedPacket;
import com.aryan.dpi_engine.parser.model.RawPacket;


public class PacketParser {

    // TCP Flag constants
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    // Protocol numbers
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    // EtherType values
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP  = 0x0806;

    /**
     * Parse a raw packet and fill in the ParsedPacket structure
     */
    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        // Initialize parsed packet
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;
        parsed.hasIp = false;
        parsed.hasTcp = false;
        parsed.hasUdp = false;
        parsed.payloadLength = 0;
        parsed.payloadOffset = -1;

        byte[] data = raw.data;
        int len = data.length;
        int[] offset = {0};

        // Parse Ethernet header first
        if (!parseEthernet(data, len, parsed, offset)) {
            return false;
        }

        // Parse IP layer if it's an IPv4 packet
        if (parsed.etherType == ETHERTYPE_IPV4) {
            if (!parseIPv4(data, len, parsed, offset)) {
                return false;
            }

            // Parse transport layer based on protocol
            if (parsed.protocol == PROTO_TCP) {
                if (!parseTCP(data, len, parsed, offset)) {
                    return false;
                }
            } else if (parsed.protocol == PROTO_UDP) {
                if (!parseUDP(data, len, parsed, offset)) {
                    return false;
                }
            }
        }

        // Set payload information
        if (offset[0] < len) {
            parsed.payloadLength = len - offset[0];
            parsed.payloadOffset = offset[0];
        } else {
            parsed.payloadLength = 0;
            parsed.payloadOffset = -1;
        }

        return true;
    }

    private static boolean parseEthernet(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        // Ethernet header is 14 bytes
        final int ETH_HEADER_LEN = 14;

        if (len < ETH_HEADER_LEN) {
            return false;
        }

        // Parse destination MAC (bytes 0-5)
        parsed.destMac = macToString(data, 0);

        // Parse source MAC (bytes 6-11)
        parsed.srcMac = macToString(data, 6);

        // Parse EtherType (bytes 12-13, big-endian)
        parsed.etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);

        offset[0] = ETH_HEADER_LEN;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        // Minimum IPv4 header is 20 bytes
        final int MIN_IP_HEADER_LEN = 20;

        if (len < offset[0] + MIN_IP_HEADER_LEN) {
            return false;
        }

        int ipStart = offset[0];

        // First byte: version (4 bits) + IHL (4 bits)
        int versionIhl = data[ipStart] & 0xFF;
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;

        if (parsed.ipVersion != 4) {
            return false;
        }

        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < MIN_IP_HEADER_LEN || len < offset[0] + ipHeaderLen) {
            return false;
        }

        // Parse fields
        parsed.ttl = data[ipStart + 8] & 0xFF;
        parsed.protocol = data[ipStart + 9] & 0xFF;

        // Source IP (bytes 12-15) - stored in network byte order
        long srcIp = ((data[ipStart + 12] & 0xFFL)) |
                ((data[ipStart + 13] & 0xFFL) << 8) |
                ((data[ipStart + 14] & 0xFFL) << 16) |
                ((data[ipStart + 15] & 0xFFL) << 24);
        parsed.srcIp = ipToString(srcIp);

        // Destination IP (bytes 16-19)
        long destIp = ((data[ipStart + 16] & 0xFFL)) |
                ((data[ipStart + 17] & 0xFFL) << 8) |
                ((data[ipStart + 18] & 0xFFL) << 16) |
                ((data[ipStart + 19] & 0xFFL) << 24);
        parsed.destIp = ipToString(destIp);

        parsed.hasIp = true;
        offset[0] += ipHeaderLen;

        return true;
    }

    private static boolean parseTCP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        // Minimum TCP header is 20 bytes
        final int MIN_TCP_HEADER_LEN = 20;

        if (len < offset[0] + MIN_TCP_HEADER_LEN) {
            return false;
        }

        int tcpStart = offset[0];

        // Source port (bytes 0-1)
        parsed.srcPort = ((data[tcpStart] & 0xFF) << 8) | (data[tcpStart + 1] & 0xFF);

        // Destination port (bytes 2-3)
        parsed.destPort = ((data[tcpStart + 2] & 0xFF) << 8) | (data[tcpStart + 3] & 0xFF);

        // Sequence number (bytes 4-7)
        parsed.seqNumber = ((data[tcpStart + 4] & 0xFFL) << 24) |
                ((data[tcpStart + 5] & 0xFFL) << 16) |
                ((data[tcpStart + 6] & 0xFFL) << 8) |
                (data[tcpStart + 7] & 0xFFL);

        // Acknowledgment number (bytes 8-11)
        parsed.ackNumber = ((data[tcpStart + 8] & 0xFFL) << 24) |
                ((data[tcpStart + 9] & 0xFFL) << 16) |
                ((data[tcpStart + 10] & 0xFFL) << 8) |
                (data[tcpStart + 11] & 0xFFL);

        // Data offset (upper 4 bits of byte 12) - header length in 32-bit words
        int dataOffset = (data[tcpStart + 12] >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;

        // Flags (byte 13)
        parsed.tcpFlags = data[tcpStart + 13] & 0xFF;

        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < offset[0] + tcpHeaderLen) {
            return false;
        }

        parsed.hasTcp = true;
        offset[0] += tcpHeaderLen;

        return true;
    }

    private static boolean parseUDP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        // UDP header is always 8 bytes
        final int UDP_HEADER_LEN = 8;

        if (len < offset[0] + UDP_HEADER_LEN) {
            return false;
        }

        int udpStart = offset[0];

        // Source port (bytes 0-1)
        parsed.srcPort = ((data[udpStart] & 0xFF) << 8) | (data[udpStart + 1] & 0xFF);

        // Destination port (bytes 2-3)
        parsed.destPort = ((data[udpStart + 2] & 0xFF) << 8) | (data[udpStart + 3] & 0xFF);

        parsed.hasUdp = true;
        offset[0] += UDP_HEADER_LEN;

        return true;
    }

    // Helper functions

    public static String macToString(byte[] mac, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", mac[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(long ip) {
        return ((ip >> 0) & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 24) & 0xFF);
    }

    public static String protocolToString(int protocol) {
        switch (protocol) {
            case PROTO_ICMP: return "ICMP";
            case PROTO_TCP:  return "TCP";
            case PROTO_UDP:  return "UDP";
            default: return "Unknown(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder result = new StringBuilder();
        if ((flags & TCP_SYN) != 0) result.append("SYN ");
        if ((flags & TCP_ACK) != 0) result.append("ACK ");
        if ((flags & TCP_FIN) != 0) result.append("FIN ");
        if ((flags & TCP_RST) != 0) result.append("RST ");
        if ((flags & TCP_PSH) != 0) result.append("PSH ");
        if ((flags & TCP_URG) != 0) result.append("URG ");
        if (result.length() > 0) {
            result.setLength(result.length() - 1); // Remove trailing space
        }
        return result.length() == 0 ? "none" : result.toString();
    }
}
