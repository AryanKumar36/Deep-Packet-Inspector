package com.aryan.dpi_engine.dpi.inspection;

import com.aryan.dpi_engine.util.ByteReader;

import java.util.Optional;

public class DnsQueryExtractor {
    public static boolean isDnsQuery(byte[] payload)    {

        //DNS Header Length is always 12
        if(payload.length< 12) return false;

        //Check for query vs response
        // 0 = query
        // 1 = response
        if ((payload[2]& 0x80)!= 0) return false;

        //Qdcount is number of question
        //Standard DNS query carries max 1 question
        int qdcount = ByteReader.readUnit16BE(payload, 4);
        return qdcount>0;
    }

    public static Optional<String> extract(byte[] payload)
    {
        if(!isDnsQuery(payload)) return Optional.empty();

        //Skipping DNS header
        int offset = 12;

        // Initialising Mutable String
        StringBuilder domain;
        domain = new StringBuilder();

        while (offset < payload.length)
        {
            int len = payload[offset] & 0xFF;

            //End of domain
            if(len == 0) break;

            //DNS label max length = 63 bytes
            if(len> 63 || offset + len >= payload.length) break;
            offset++;

            //Add '.' after each append
            if(!domain.isEmpty()) domain.append('.');

            //appending the domain
            domain.append(new String(payload, offset, len));
            offset+=len;

        }
        return domain.isEmpty() ? Optional.empty() : Optional.of(domain.toString());
    }
}
