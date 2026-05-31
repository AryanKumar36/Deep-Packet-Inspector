package com.aryan.dpi_engine.dpi.engine;


import com.aryan.dpi_engine.dpi.model.*;
import com.aryan.dpi_engine.model.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * FP Manager - Creates and manages multiple FP threads
 */
public class FPManager {
    private final List<FastPathProcessor> fps = new ArrayList<>();

    public FPManager(int numFps, RuleManager ruleManager,
                     BiConsumer<PacketJob, PacketAction> outputCallback) {
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
        }
        System.out.println("[FPManager] Created " + numFps + " fast path processors");
    }

    public void startAll() {
        for (FastPathProcessor fp : fps) fp.start();
    }

    public void stopAll() {
        for (FastPathProcessor fp : fps) fp.stop();
    }

    public FastPathProcessor getFP(int id) { return fps.get(id); }

    public ThreadSafeQueue<PacketJob> getFPQueue(int id) { return fps.get(id).getInputQueue(); }

    public List<ThreadSafeQueue<PacketJob>> getQueuePtrs() {
        List<ThreadSafeQueue<PacketJob>> ptrs = new ArrayList<>();
        for (FastPathProcessor fp : fps) {
            ptrs.add(fp.getInputQueue());
        }
        return ptrs;
    }

    public int getNumFPs() { return fps.size(); }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats stats = new AggregatedStats();
        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats fpStats = fp.getStats();
            stats.totalProcessed += fpStats.packetsProcessed;
            stats.totalForwarded += fpStats.packetsForwarded;
            stats.totalDropped += fpStats.packetsDropped;
            stats.totalConnections += fpStats.connectionsTracked;
        }
        return stats;
    }

    public String generateClassificationReport() {
        Map<AppType, Long> appCounts = new HashMap<>();
        Map<String, Long> domainCounts = new HashMap<>();
        long totalClassified = 0;
        long totalUnknown = 0;

        for (FastPathProcessor fp : fps) {
            fp.getConnectionTracker().forEach(conn -> {
                appCounts.merge(conn.appType, 1L, Long::sum);
                if (conn.sni != null && !conn.sni.isEmpty()) {
                    domainCounts.merge(conn.sni, 1L, Long::sum);
                }
            });
        }

        for (Map.Entry<AppType, Long> e : appCounts.entrySet()) {
            if (e.getKey() == AppType.UNKNOWN) totalUnknown += e.getValue();
            else totalClassified += e.getValue();
        }

        StringBuilder ss = new StringBuilder();
        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║                 APPLICATION CLASSIFICATION REPORT             ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0 ? (100.0 * totalClassified / total) : 0;
        double unknownPct = total > 0 ? (100.0 * totalUnknown / total) : 0;

        ss.append(String.format("║ Total Connections:    %10d                           ║\n", total));
        ss.append(String.format("║ Classified:           %10d (%.1f%%)                  ║\n", totalClassified, classifiedPct));
        ss.append(String.format("║ Unidentified:         %10d (%.1f%%)                  ║\n", totalUnknown, unknownPct));

        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║                    APPLICATION DISTRIBUTION                   ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appCounts.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0;
            int barLen = (int) (pct / 5);
            String bar = "#".repeat(barLen);
            ss.append(String.format("║ %-15s%8d %5.1f%% %-20s   ║\n",
                AppType.toString(entry.getKey()), entry.getValue(), pct, bar));
        }

        ss.append("╚══════════════════════════════════════════════════════════════╝\n");
        return ss.toString();
    }

    public static class AggregatedStats {
        public long totalProcessed;
        public long totalForwarded;
        public long totalDropped;
        public long totalConnections;
    }
}
