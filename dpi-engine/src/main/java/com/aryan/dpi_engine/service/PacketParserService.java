package com.aryan.dpi_engine.service;

import com.aryan.dpi_engine.model.ParsedPacket;
import com.aryan.dpi_engine.model.RawPacket;
import org.springframework.stereotype.Service;

import static com.aryan.dpi_engine.util.Helpers.*;

@Service
public class PacketParserService {


    public boolean parse(RawPacket raw, ParsedPacket parsed) {


        byte[] data = raw.getData();
        int len = data.length;
        int offset = 0;

        parsed.timestampSec = raw.getTimestampSec();
        parsed.timestampUsec = raw.getTimestampUsec();

        // Ethernet (0-13)
        if (len < 14) return false;
        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);
        parsed.etherType = readUInt16(data, 12);
        offset = 14;

        //IPv4 only (14 + ihl*4)
        if (parsed.etherType != 0x800) return true;
        if (len < offset + 20) return false;

        int versionIhl = data[offset] & 0xFF;
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;
        int ipHeaderLen = ihl * 4;

        if (parsed.ipVersion != 4 || len < offset + ipHeaderLen) return false;

        parsed.ttl = data[offset + 8] & 0xFF;
        parsed.protocol = data[offset + 9] & 0xFF;
        parsed.srcIp = ipToString(data, offset + 12);
        parsed.destIp = ipToString(data, offset + 16);
        parsed.hasIp = true;

        // 14 + (ihl*4)
        offset += ipHeaderLen;

        //TCP
        if (parsed.protocol == 6) {
            if (len < offset + 20) return false;

            parsed.srcPort = readUInt16(data, offset);
            parsed.destPort = readUInt16(data, offset + 2);
            parsed.seqNumber = readUInt32(data, offset + 4);
            parsed.ackNumber = readUInt32(data, offset + 8);

            int dataOffset = (data[offset + 12] >> 4) & 0x0F;
            int tcpHeaderLen = dataOffset * 4;
            parsed.tcpFlags = data[offset + 13];

            if (len < offset + tcpHeaderLen) return false;

            parsed.hasTcp = true;

            // offset = ethernet + ip header + tcpHeaderLen
            offset += tcpHeaderLen;
        }

        //UDP
        else if (parsed.protocol == 17) {

            if (len < offset + 8) return false;

            parsed.srcPort = readUInt16(data, offset);
            parsed.destPort = readUInt16(data, offset + 2);
            parsed.hasUdp = true;

            //offset = ether + ip header + 8 as udp
            offset += 8;

        }
        //payload
        if (offset < len) {
            parsed.payloadLength = len - offset;
            parsed.payload = new byte[parsed.payloadLength];
            System.arraycopy(data, offset, parsed.payload, 0, parsed.payloadLength);

        }

        return true;

    }


}
