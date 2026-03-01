package com.aryan.dpi_engine.util;

public final class ByteReader {

    private ByteReader() {
    }



    public static int readUnit16BE(byte[] data, int pos) {
        return ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
    }

    public static int readUnit24BE(byte[] data, int pos) {
        return ((data[pos] & 0xFF) << 16 |
                ((data[pos + 1]) & 0xFF << 8) |
                (data[pos + 2] & 0xFF)
        );
    }
}
