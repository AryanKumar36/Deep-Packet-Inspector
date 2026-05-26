package com.aryan.dpi_engine.dpi.inspection;

import java.util.Optional;


// May need improvement
public class QuicSniExtractor {

    //Cause Initial has SNI and in plaintext
    //Rest is encrypted
    public static String extract(byte[] payload, int offset, int length) {
        if (!isQUICInitial(payload, offset, length)) {
            return null;
        }

        // Search for TLS Client Hello pattern within the QUIC packet
        for (int i = offset; i + 50 < offset + length; i++) {
            if ((payload[i] & 0xFF) == 0x01) { // Client Hello handshake type
                // Try to extract SNI starting from here
                int adjustedOffset = i - 5;
                if (adjustedOffset >= offset) {
                    String result = TlsSniExtractor.extract(payload, adjustedOffset, offset + length - adjustedOffset);
                    if (result != null) return result;
                }
            }
        }

        return null;
    }

    /**
     * Check if this looks like a QUIC Initial packet
     */
    public static boolean isQUICInitial(byte[] payload, int offset, int length) {
        if (length < 5) return false;

        // QUIC long header starts with 1 bit set (form bit)
        int firstByte = payload[offset] & 0xFF;

        // Long header form
        if ((firstByte & 0x80) == 0) return false;

        return true;
    }
}

