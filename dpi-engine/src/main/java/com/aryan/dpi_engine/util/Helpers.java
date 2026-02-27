package com.aryan.dpi_engine.util;


import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class Helpers {
    private Helpers() {
        // prevent instantiation
    }

    public static int readUInt16(byte[] data, int pos) {
        return ByteBuffer.wrap(data, pos, 2)
                .order(ByteOrder.BIG_ENDIAN)
                .getShort() & 0xFFFF;
    }

    public static long readUInt32(byte[] data, int pos) {
        return ByteBuffer.wrap(data, pos, 4)
                .order(ByteOrder.BIG_ENDIAN)
                .getInt() & 0xFFFFFFFFL;
    }

    public static String macToString(byte[] data, int pos) {
        return String.format(
                "%02x:%02x:%02x:%02x:%02x:%02x",
                data[pos] & 0xFF, data[pos + 1] & 0xFF,
                data[pos + 2] & 0xFF, data[pos + 3] & 0xFF,
                data[pos + 4] & 0xFF, data[pos + 5] & 0xFF
        );
    }

    public static String ipToString(byte[] data, int pos) {
        return (data[pos] & 0xFF) + "." +
                (data[pos + 1] & 0xFF) + "." +
                (data[pos + 2] & 0xFF) + "." +
                (data[pos + 3] & 0xFF);
    }
}
