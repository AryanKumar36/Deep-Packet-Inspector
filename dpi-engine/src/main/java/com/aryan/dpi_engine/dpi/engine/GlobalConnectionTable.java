package com.aryan.dpi_engine.dpi.engine;

import com.aryan.dpi_engine.dpi.model.AppType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Global Connection Table - Aggregates stats from all FP trackers
 */
public class GlobalConnectionTable {
    private final ConnectionTracker[] trackers;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public GlobalConnectionTable(int numFps) {
        trackers = new ConnectionTracker[numFps];
    }

    /** Register an FP's tracker */
    public void registerTracker(int fpId, ConnectionTracker tracker) {
        lock.writeLock().lock();
        try {
            if (fpId < trackers.length) {
                trackers[fpId] = tracker;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** Get aggregated statistics */
    public GlobalStats getGlobalStats() {
        lock.readLock().lock();
        try {
            GlobalStats stats = new GlobalStats();
            stats.totalActiveConnections = 0;
            stats.totalConnectionsSeen = 0;
            stats.appDistribution = new HashMap<>();
            Map<String, Long> domainCounts = new HashMap<>();

            for (ConnectionTracker tracker : trackers) {
                if (tracker == null) continue;

                ConnectionTracker.TrackerStats ts = tracker.getStats();
                stats.totalActiveConnections += ts.activeConnections;
                stats.totalConnectionsSeen += ts.totalConnectionsSeen;

                // Collect app distribution
                tracker.forEach(conn -> {
                    stats.appDistribution.merge(conn.appType, 1L, Long::sum);
                    if (conn.sni != null && !conn.sni.isEmpty()) {
                        domainCounts.merge(conn.sni, 1L, Long::sum);
                    }
                });
            }

            // Get top domains
            List<Map.Entry<String, Long>> domainVec = new ArrayList<>(domainCounts.entrySet());
            domainVec.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

            int count = Math.min(domainVec.size(), 20);
            stats.topDomains = new ArrayList<>(domainVec.subList(0, count));

            return stats;
        } finally {
            lock.readLock().unlock();
        }
    }

    /** Generate report */
    public String generateReport() {
        GlobalStats stats = getGlobalStats();

        StringBuilder ss = new StringBuilder();
        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║               CONNECTION STATISTICS REPORT                    ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        ss.append(String.format("║ Active Connections:     %10d                          ║\n", stats.totalActiveConnections));
        ss.append(String.format("║ Total Connections Seen: %10d                          ║\n", stats.totalConnectionsSeen));

        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║                    APPLICATION BREAKDOWN                      ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        // Calculate total for percentages
        long total = 0;
        for (long val : stats.appDistribution.values()) {
            total += val;
        }

        // Sort by count
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.appDistribution.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0;
            ss.append(String.format("║ %-20s%10d (%5.1f%%)           ║\n",
                AppType.toString(entry.getKey()), entry.getValue(), pct));
        }

        if (!stats.topDomains.isEmpty()) {
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║                      TOP DOMAINS                             ║\n");
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");

            for (Map.Entry<String, Long> entry : stats.topDomains) {
                String domain = entry.getKey();
                if (domain.length() > 35) {
                    domain = domain.substring(0, 32) + "...";
                }
                ss.append(String.format("║ %-40s%10d           ║\n", domain, entry.getValue()));
            }
        }

        ss.append("╚══════════════════════════════════════════════════════════════╝\n");

        return ss.toString();
    }

    public static class GlobalStats {
        public long totalActiveConnections;
        public long totalConnectionsSeen;
        public Map<AppType, Long> appDistribution;
        public List<Map.Entry<String, Long>> topDomains;
    }
}
