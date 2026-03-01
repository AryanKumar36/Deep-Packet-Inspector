package com.aryan.dpi_engine.dpi.inspection;

import com.aryan.dpi_engine.util.ByteReader;

import java.util.Optional;

public class TlsSniExtractor {

    private static final byte CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final byte HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final byte SNI_TYPE_HOSTNAME = 0x00;

    public static boolean isTlsClientHello(byte[] payload) {
        //minimum TLS Record 5 bytes record Header + 4 bytes Handshake header
        if (payload.length < 9) return false;

        //First byte should be always 0x16
        if (payload[0] != CONTENT_TYPE_HANDSHAKE) return false;

        //TLS version 1.0, 1.2 and 1.3 ranges 0x0301 to 0x0303
        int version = ByteReader.readUnit16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) return false;

        //Validator to check "How many bytes follow the 5-byte header?"
        int recordLen = ByteReader.readUnit16BE(payload, 3);
        if (recordLen > payload.length - 5) return false;

        //Byte 5 = Handshake Type , Must be 0x01 (ClientHello)
        return payload[5] == HANDSHAKE_CLIENT_HELLO;
    }

    public static Optional<String> extract(byte[] payload) {
        //SNI is not present condition
        if (!isTlsClientHello(payload)) return Optional.empty();

        int offset = 5;

        int handshakeLen = ByteReader.readUnit24BE(payload, offset + 1);
        offset += 4;

        // TO Be Checked later
        if (offset + handshakeLen > payload.length) return Optional.empty();

        offset += 2; //client version
        offset += 32; //random

        //Validator to check if "Have I passed everything or TLS is broken";
        if (offset >= payload.length) return Optional.empty();

        int sessionIdLen = payload[offset] & 0xFF;
        offset += 1 + sessionIdLen;

        int cypherLen = ByteReader.readUnit16BE(payload, offset);
        offset += 2 + cypherLen;

        int compressionLen = payload[offset] & 0xFF;
        offset += 1 + compressionLen;

        int extensionLen = ByteReader.readUnit16BE(payload, offset);
        offset += 2;

        int extensionEnds = Math.min(offset + extensionLen, payload.length);

        while (offset + 4 <= extensionEnds) {
            int type = ByteReader.readUnit16BE(payload, offset);
            int len = ByteReader.readUnit16BE(payload, offset + 2);
            offset += 4;

            if (offset + len > extensionEnds) break;

            if (type == EXTENSION_SNI) {
                if (len < 5) {
                    int sniType = payload[offset + 2] & 0xFF;
                    int sniLen = ByteReader.readUnit16BE(payload, offset + 3);

                    if (sniType != SNI_TYPE_HOSTNAME) break;
                    if (sniLen > len - 5) break;

                    return Optional.of(
                            new String(payload, offset + 5, sniLen)
                    );
                }
            }
            offset += len;
        }

        return Optional.empty();

    }


}
