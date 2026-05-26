package com.aryan.dpi_engine.dpi.inspection;

import java.util.Optional;

public class HttpHostExtractor {
    public static String extract(byte[] payload, int offset, int length) {
        if (!isHTTPRequest(payload, offset, length)) {
            return null;
        }

        // Search for "Host: " header
        for (int i = offset; i + 6 < offset + length; i++) {
            // Check for header (case-insensitive "host:")
            if ((payload[i] == 'H' || payload[i] == 'h') &&
                    (payload[i + 1] == 'o' || payload[i + 1] == 'O') &&
                    (payload[i + 2] == 's' || payload[i + 2] == 'S') &&
                    (payload[i + 3] == 't' || payload[i + 3] == 'T') &&
                    payload[i + 4] == ':') {

                // Skip "Host:" and any whitespace
                int start = i + 5;
                while (start < offset + length && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                // Find end of line
                int end = start;
                while (end < offset + length && payload[end] != '\r' && payload[end] != '\n') {
                    end++;
                }

                if (end > start) {
                    String host = new String(payload, start, end - start);

                    // Remove port if present
                    int colonPos = host.indexOf(':');
                    if (colonPos != -1) {
                        host = host.substring(0, colonPos);
                    }

                    return host;
                }
            }
        }

        return null;
    }

    /**
     * Check if this looks like an HTTP request
     */
    public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
        if (length < 4) return false;

        // Check for common HTTP methods
        String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};

        for (String method : methods) {
            boolean match = true;
            for (int i = 0; i < 4; i++) {
                if (payload[offset + i] != method.charAt(i)) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }

        return false;
    }
}

