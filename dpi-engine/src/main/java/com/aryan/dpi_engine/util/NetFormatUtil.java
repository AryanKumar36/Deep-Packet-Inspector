package com.aryan.dpi_engine.util;

public final class NetFormatUtil {
    private NetFormatUtil(){}

    public static String ipToString(int ip)
    {
        return (ip & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 24) & 0xFF);
    }
}
