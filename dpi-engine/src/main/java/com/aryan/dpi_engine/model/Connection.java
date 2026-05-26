package com.aryan.dpi_engine.model;

import com.aryan.dpi_engine.dpi.model.AppType;

public class Connection {
    public FiveTuple tuple = new FiveTuple();
    public ConnectionState state = ConnectionState.NEW;
    public AppType appType = AppType.UNKNOWN;
    public String sni = "";  // Server Name Indication (if detected)

    public long packetsIn = 0;
    public long packetsOut = 0;
    public long bytesIn = 0;
    public long bytesOut = 0;

    public long firstSeenNanos = System.nanoTime();
    public long lastSeenNanos = System.nanoTime();

    public PacketAction action = PacketAction.FORWARD;

    // For TCP state tracking
    public boolean synSeen = false;
    public boolean synAckSeen = false;
    public boolean finSeen = false;
}

