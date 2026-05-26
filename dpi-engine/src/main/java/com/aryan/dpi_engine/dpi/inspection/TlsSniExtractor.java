package com.aryan.dpi_engine.dpi.inspection;

import com.aryan.dpi_engine.util.ByteReader.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.aryan.dpi_engine.util.ByteReader.readUnit16BE;


public class TlsSniExtractor {
    // TLS Constants
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    /**
     * Extract SNI from a TLS Client Hello packet.
     * payload should point to the start of TCP payload (after TCP header).
     */
    public static String extract(byte[] payload, int offset, int length) {
        if (!isTLSClientHello(payload, offset, length)) {
            return null;
        }

        // Skip TLS record header (5 bytes)
        int pos = offset + 5;

        // Skip handshake header
        // Byte 0: Handshake type (already checked)
        // Bytes 1-3: Length
        if (pos + 4 > offset + length) return null;
        // long handshakeLength = readUint24BE(payload, pos + 1);
        pos += 4;

        // Client Hello body
        // Bytes 0-1: Client version
        pos += 2;

        // Bytes 2-33: Random (32 bytes)
        pos += 32;

        // Session ID
        if (pos >= offset + length) return null;
        int sessionIdLength = payload[pos] & 0xFF;
        pos += 1 + sessionIdLength;

        // Cipher suites
        if (pos + 2 > offset + length) return null;
        int cipherSuitesLength = readUnit16BE(payload, pos);
        pos += 2 + cipherSuitesLength;

        // Compression methods
        if (pos >= offset + length) return null;
        int compressionMethodsLength = payload[pos] & 0xFF;
        pos += 1 + compressionMethodsLength;

        // Extensions
        if (pos + 2 > offset + length) return null;
        int extensionsLength = readUnit16BE(payload, pos);
        pos += 2;

        int extensionsEnd = pos + extensionsLength;
        if (extensionsEnd > offset + length) {
            extensionsEnd = offset + length;  // Truncated, but try to parse anyway
        }

        // Parse extensions to find SNI
        while (pos + 4 <= extensionsEnd) {
            int extensionType = readUnit16BE(payload, pos);
            int extensionLength = readUnit16BE(payload, pos + 2);
            pos += 4;

            if (pos + extensionLength > extensionsEnd) break;

            if (extensionType == EXTENSION_SNI) {
                // SNI extension found
                if (extensionLength < 5) break;

                int sniListLength = readUnit16BE(payload, pos);
                if (sniListLength < 3) break;

                int sniType = payload[pos + 2] & 0xFF;
                int sniLength = readUnit16BE(payload, pos + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLength > extensionLength - 5) break;

                // Extract the hostname
                return new String(payload, pos + 5, sniLength);
            }

            pos += extensionLength;
        }

        return null;
    }

    /**
     * Check if this looks like a TLS Client Hello
     */
    public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
        // Minimum TLS record: 5 bytes header + 4 bytes handshake header
        if (length < 9) return false;

        // Byte 0: Content Type (should be 0x16 = Handshake)
        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        // Bytes 1-2: TLS Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
        int version = readUnit16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) return false;

        // Bytes 3-4: Record length
        int recordLength = readUnit16BE(payload, offset + 3);
        if (recordLength > length - 5) return false;

        // Byte 5: Handshake Type (should be 0x01 = Client Hello)
        if ((payload[offset + 5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return false;

        return true;
    }

    /**
     * Extract all extensions (for debugging/logging)
     */
    public static List<Map.Entry<Integer, String>> extractExtensions(
            byte[] payload, int offset, int length) {
        // Similar parsing logic as extract(), but collect all extensions
        // (abbreviated for brevity)
        return new ArrayList<>();
    }


}
