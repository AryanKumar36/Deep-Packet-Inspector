package com.aryan.dpi_engine.parser.service;

public class PortableNet {

    public static int swapBytes16(int value) {
        return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
    }

    public static long swapBytes32(long value) {
        return ((value & 0xFF000000L) >> 24) |
                ((value & 0x00FF0000L) >> 8)  |
                ((value & 0x0000FF00L) << 8)  |
                ((value & 0x000000FFL) << 24);
    }

    /**
     * Java is always big-endian at the bytecode level,
     */
    public static boolean isLittleEndian() {
        // Java uses big-endian by default for multi-byte values,
        // but network data read byte-by-byte is just raw bytes.
        // We assume x86/little-endian host for compatibility.
        return java.nio.ByteOrder.nativeOrder() == java.nio.ByteOrder.LITTLE_ENDIAN;
    }

    /** Network to host byte order (16-bit) */
    public static int netToHost16(int netValue) {
        if (isLittleEndian()) {
            return swapBytes16(netValue);
        }
        return netValue;
    }

    /** Network to host byte order (32-bit) */
    public static long netToHost32(long netValue) {
        if (isLittleEndian()) {
            return swapBytes32(netValue);
        }
        return netValue;
    }

    /** Host to network byte order (16-bit) */
    public static int hostToNet16(int hostValue) {
        return netToHost16(hostValue);
    }

    /** Host to network byte order (32-bit) */
    public static long hostToNet32(long hostValue) {
        return netToHost32(hostValue);
    }
}
