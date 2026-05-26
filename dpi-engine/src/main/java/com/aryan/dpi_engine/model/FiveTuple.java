package com.aryan.dpi_engine.model;


public class FiveTuple {
    public long srcIp;    // uint32 stored as long to avoid sign issues
    public long dstIp;
    public int srcPort;   // uint16 stored as int
    public int dstPort;
    public int protocol;  // TCP=6, UDP=17

    public FiveTuple() {
    }

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    /**
     * Create reverse tuple (for matching bidirectional flows)
     */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiveTuple other = (FiveTuple) o;
        return srcIp == other.srcIp &&
                dstIp == other.dstIp &&
                srcPort == other.srcPort &&
                dstPort == other.dstPort &&
                protocol == other.protocol;
    }

    @Override
    public int hashCode() {

        long h = 0;
        h ^= Long.hashCode(srcIp) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Long.hashCode(dstIp) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(srcPort) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(dstPort) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(protocol) + 0x9e3779b9L + (h << 6) + (h >> 2);
        return (int) h;
    }

    @Override
    public String toString() {
        return formatIP(srcIp) + ":" + srcPort +
                " -> " +
                formatIP(dstIp) + ":" + dstPort +
                " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") + ")";
    }

    public static String formatIP(long ip) {
        return ((ip) & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 24) & 0xFF);
    }
}
