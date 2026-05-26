package com.aryan.dpi_engine.dpi.inspection;

import com.aryan.dpi_engine.util.ByteReader;

import java.util.Optional;

public class DnsQueryExtractor {

    /**
     * Extract queried domain from DNS request
     */
    public static String extractQuery(byte[] payload, int offset, int length) {
        if (!isDNSQuery(payload, offset, length)) {
            return null;
        }

        // DNS query starts at byte 12
        int pos = offset + 12;
        StringBuilder domain = new StringBuilder();

        while (pos < offset + length) {
            int labelLength = payload[pos] & 0xFF;

            if (labelLength == 0) {
                // End of domain name
                break;
            }

            if (labelLength > 63) {
                // Compression pointer or invalid
                break;
            }

            pos++;
            if (pos + labelLength > offset + length) break;

            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, pos, labelLength));
            pos += labelLength;
        }

        return domain.length() == 0 ? null : domain.toString();
    }

    /**
     * Check if this is a DNS query (not response)
     */
    public static boolean isDNSQuery(byte[] payload, int offset, int length) {
        // Minimum DNS header is 12 bytes
        if (length < 12) return false;

        // Check QR bit (byte 2, bit 7) - should be 0 for query
        int flags = payload[offset + 2] & 0xFF;
        if ((flags & 0x80) != 0) return false; // This is a response, not a query

        // Check QDCOUNT (bytes 4-5) - should be > 0
        int qdcount = ((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF);
        if (qdcount == 0) return false;

        return true;
    }
}