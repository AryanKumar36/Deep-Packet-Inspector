package com.aryan.dpi_engine.dpi.engine;



import com.aryan.dpi_engine.dpi.model.AppType;
import com.aryan.dpi_engine.model.*;
import com.aryan.dpi_engine.model.Connection;
import com.aryan.dpi_engine.model.FiveTuple;

import java.util.*;
import java.util.function.Consumer;

/**
 * Connection Tracker - Maintains flow table for all active connections.
 * Each FP thread has its own ConnectionTracker instance.
 */
public class ConnectionTracker {
    private final int fpId;
    private final int maxConnections;

    // Connection table
    private final Map<FiveTuple, Connection> connections = new HashMap<>();

    // Statistics
    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public ConnectionTracker(int fpId) {
        this(fpId, 100000);
    }

    /** Get or create connection entry */
    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }

        // Check if we need to evict old connections
        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        // Create new connection
        conn = new Connection();
        conn.tuple = tuple;
        conn.state = ConnectionState.NEW;
        conn.firstSeenNanos = System.nanoTime();
        conn.lastSeenNanos = conn.firstSeenNanos;

        connections.put(tuple, conn);
        totalSeen++;

        return conn;
    }

    /** Get existing connection (returns null if not found) */
    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }

        // Try reverse tuple (for bidirectional matching)
        return connections.get(tuple.reverse());
    }

    /** Update connection with new packet */
    public void updateConnection(Connection conn, long packetSize, boolean isOutbound) {
        if (conn == null) return;

        conn.lastSeenNanos = System.nanoTime();

        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    /** Mark connection as classified */
    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;

        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni = sni;
            conn.state = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    /** Mark connection as blocked */
    public void blockConnection(Connection conn) {
        if (conn == null) return;

        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    /** Mark connection as closed */
    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    /** Remove timed-out connections. Returns number removed. */
    public int cleanupStale(long timeoutSeconds) {
        long now = System.nanoTime();
        long timeoutNanos = timeoutSeconds * 1_000_000_000L;
        int removed = 0;

        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<FiveTuple, Connection> entry = it.next();
            long age = now - entry.getValue().lastSeenNanos;

            if (age > timeoutNanos || entry.getValue().state == ConnectionState.CLOSED) {
                it.remove();
                removed++;
            }
        }

        return removed;
    }

    /** Get all connections (for reporting) */
    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    /** Get active connection count */
    public int getActiveCount() {
        return connections.size();
    }

    /** Get statistics */
    public TrackerStats getStats() {
        TrackerStats stats = new TrackerStats();
        stats.activeConnections = connections.size();
        stats.totalConnectionsSeen = totalSeen;
        stats.classifiedConnections = classifiedCount;
        stats.blockedConnections = blockedCount;
        return stats;
    }

    /** Clear all connections */
    public void clear() {
        connections.clear();
    }

    /** Iteration callback for all connections */
    public void forEach(Consumer<Connection> callback) {
        for (Connection conn : connections.values()) {
            callback.accept(conn);
        }
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;

        Map.Entry<FiveTuple, Connection> oldest = null;
        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (oldest == null || entry.getValue().lastSeenNanos < oldest.getValue().lastSeenNanos) {
                oldest = entry;
            }
        }

        if (oldest != null) {
            connections.remove(oldest.getKey());
        }
    }

    public static class TrackerStats {
        public long activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;
    }
}
