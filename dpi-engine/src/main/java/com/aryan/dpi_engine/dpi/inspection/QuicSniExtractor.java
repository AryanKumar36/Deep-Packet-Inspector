package com.aryan.dpi_engine.dpi.inspection;

import java.util.Optional;


// May need improvement
public class QuicSniExtractor {

    //Cause Initial has SNI and in plaintext
    //Rest is encrypted
    public static boolean isQuicInitial(byte[] payload){
        return payload.length >= 5 && (payload[0] & 0x80) != 0;
    }

    public static Optional<String> extract (byte[] payload)
    {
        if(!isQuicInitial(payload)) return Optional.empty();

        for(int i = 0; i + 50 < payload.length; i++)
        {
            if(payload[i] == 0x01)
            {
                // Making look like TLS so I can reuse the code
                byte[] slice = new byte[payload.length - i + 5];
                System.arraycopy(payload, i -5,slice,0,slice.length);
                return TlsSniExtractor.extract(slice);
            }
        }
        return Optional.empty();
    }
}
