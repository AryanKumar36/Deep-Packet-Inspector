package com.aryan.dpi_engine.parser.service;

import com.aryan.dpi_engine.parser.model.PcapGlobalHeader;
import com.aryan.dpi_engine.parser.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader {
    // Magic numbers for PCAP files
    private static final long PCAP_MAGIC_NATIVE  = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    private DataInputStream file;
    private PcapGlobalHeader globalHeader = new PcapGlobalHeader();
    private boolean needsByteSwap = false;
    private boolean isOpen = false;

    public PcapReader() {}

    /**
     * Open a pcap file for reading
     */
    public boolean open(String filename) {
        close();

        try {
            file = new DataInputStream(new BufferedInputStream(new FileInputStream(filename)));
        } catch (FileNotFoundException e) {
            System.err.println("Error: Could not open file: " + filename);
            return false;
        }

        // Read the global header (first 24 bytes of the file)
        try {
            byte[] headerBytes = new byte[24];
            file.readFully(headerBytes);
            ByteBuffer buf = ByteBuffer.wrap(headerBytes).order(ByteOrder.LITTLE_ENDIAN);

            globalHeader.magicNumber = buf.getInt() & 0xFFFFFFFFL;
            globalHeader.versionMajor = buf.getShort() & 0xFFFF;
            globalHeader.versionMinor = buf.getShort() & 0xFFFF;
            globalHeader.thiszone = buf.getInt();
            globalHeader.sigfigs = buf.getInt() & 0xFFFFFFFFL;
            globalHeader.snaplen = buf.getInt() & 0xFFFFFFFFL;
            globalHeader.network = buf.getInt() & 0xFFFFFFFFL;
        } catch (IOException e) {
            System.err.println("Error: Could not read PCAP global header");
            close();
            return false;
        }

        // Check the magic number to determine byte order
        if (globalHeader.magicNumber == PCAP_MAGIC_NATIVE) {
            needsByteSwap = false;
        } else if (globalHeader.magicNumber == PCAP_MAGIC_SWAPPED) {
            needsByteSwap = true;
            // Swap the header fields we've already read
            globalHeader.versionMajor = (int) maybeSwap16(globalHeader.versionMajor);
            globalHeader.versionMinor = (int) maybeSwap16(globalHeader.versionMinor);
            globalHeader.snaplen = maybeSwap32(globalHeader.snaplen);
            globalHeader.network = maybeSwap32(globalHeader.network);
        } else {
            System.err.println("Error: Invalid PCAP magic number: 0x" +
                    Long.toHexString(globalHeader.magicNumber));
            close();
            return false;
        }

        isOpen = true;

        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
        System.out.println("  Snaplen: " + globalHeader.snaplen + " bytes");
        System.out.println("  Link type: " + globalHeader.network +
                (globalHeader.network == 1 ? " (Ethernet)" : ""));

        return true;
    }

    /**
     * Close the file
     */
    public void close() {
        if (file != null) {
            try {
                file.close();
            } catch (IOException ignored) {}
            file = null;
        }
        isOpen = false;
        needsByteSwap = false;
    }

    /**
     * Read the next packet, returns false if no more packets
     */
    public boolean readNextPacket(RawPacket packet) {
        if (!isOpen || file == null) {
            return false;
        }

        try {
            // Read the packet header (16 bytes)
            byte[] headerBytes = new byte[16];
            file.readFully(headerBytes);
            ByteBuffer buf = ByteBuffer.wrap(headerBytes).order(ByteOrder.LITTLE_ENDIAN);

            packet.header.tsSec = buf.getInt() & 0xFFFFFFFFL;
            packet.header.tsUsec = buf.getInt() & 0xFFFFFFFFL;
            packet.header.inclLen = buf.getInt() & 0xFFFFFFFFL;
            packet.header.origLen = buf.getInt() & 0xFFFFFFFFL;

            // Swap bytes if needed
            if (needsByteSwap) {
                packet.header.tsSec = maybeSwap32(packet.header.tsSec);
                packet.header.tsUsec = maybeSwap32(packet.header.tsUsec);
                packet.header.inclLen = maybeSwap32(packet.header.inclLen);
                packet.header.origLen = maybeSwap32(packet.header.origLen);
            }

            // Sanity check on packet length
            if (packet.header.inclLen > globalHeader.snaplen ||
                    packet.header.inclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + packet.header.inclLen);
                return false;
            }

            // Read the packet data
            packet.data = new byte[(int) packet.header.inclLen];
            file.readFully(packet.data);

            return true;
        } catch (EOFException e) {
            return false;  // End of file
        } catch (IOException e) {
            System.err.println("Error: Could not read packet data");
            return false;
        }
    }

    /** Get the global header info */
    public PcapGlobalHeader getGlobalHeader() { return globalHeader; }

    /** Check if file is open */
    public boolean isOpen() { return isOpen; }

    /** Check if we need to swap byte order */
    public boolean needsByteSwap() { return needsByteSwap; }

    // Helper to swap bytes if needed
    private int maybeSwap16(int value) {
        if (!needsByteSwap) return value;
        return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
    }

    private long maybeSwap32(long value) {
        if (!needsByteSwap) return value;
        return ((value & 0xFF000000L) >> 24) |
                ((value & 0x00FF0000L) >> 8)  |
                ((value & 0x0000FF00L) << 8)  |
                ((value & 0x000000FFL) << 24);
    }
}
