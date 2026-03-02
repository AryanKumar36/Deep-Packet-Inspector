package com.aryan.dpi_engine.dpi.inspection;

import java.util.Optional;

public class HttpHostExtractor {
    private static final String[] METHODS = {"GET ", "POST", "PUT ", "HEAD","DELE", "PATC", "OPTI" };

    //Iterate and compare the payload by 4 chars and if it gets
    public static boolean isHttpRequest(byte[] payload){
        if(payload.length < 4) return false;
        for(String m: METHODS)
        {
            if(new String(payload, 0,4).equalsIgnoreCase(m))
            {
                return true;
            }
        }
        return false;

    }

    public static Optional<String> extract(byte[] payload)
    {
        if(!isHttpRequest(payload)) return Optional.empty();

        for(int i = 0; i + 6 < payload.length; i++)
        {
            if((payload[i] == 'H' || payload[i] == 'h') &&
                    (payload[i+1] == 'o' || payload[i+1] == 'O') &&
                    (payload[i+2] == 's' || payload[i+2] == 'S') &&
                    (payload[i+3] == 't' || payload[i+3] == 'T') &&
                    payload[i+4] == ':') {

                //Skipping whitespace
                int start = i+5;
                while (start < payload.length &&
                        (payload[start] == ' ' || payload[start] == '\t')){
                    start++;
                }

                //Finding end of header line
                int end = start;

                // not (A or B) = not A and not B
                while(end<payload.length && payload[end]!= '\r' && payload[end]!='\n')
                {
                    end++;
                }

                //remove Port if any Host: example.com:8080
                if(end > start)
                {
                    String host = new String(payload, start, end-start);
                    int colon = host.indexOf(':');
                    return Optional.of(colon >0 ? host.substring(0,colon) : host);

                }


            }
        }

        return Optional.empty();

    }
}
