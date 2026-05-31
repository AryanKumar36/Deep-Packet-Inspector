package com.aryan.dpi_engine.dpi.engine;



import com.aryan.dpi_engine.model.FiveTuple;
import com.aryan.dpi_engine.model.PacketJob;

import java.util.*;

/**
 * LB Manager - Creates and manages multiple LB threads
 */
public class LBManager {
    private final List<LoadBalancer> lbs = new ArrayList<>();
    private final int fpsPerLb;

    public LBManager(int numLbs, int fpsPerLb, List<ThreadSafeQueue<PacketJob>> fpQueues) {
        this.fpsPerLb = fpsPerLb;

        for (int lbId = 0; lbId < numLbs; lbId++) {
            List<ThreadSafeQueue<PacketJob>> lbFpQueues = new ArrayList<>();
            int fpStart = lbId * fpsPerLb;

            for (int i = 0; i < fpsPerLb; i++) {
                lbFpQueues.add(fpQueues.get(fpStart + i));
            }

            lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
        }

        System.out.println("[LBManager] Created " + numLbs + " load balancers, " +
            fpsPerLb + " FPs each");
    }

    public void startAll() {
        for (LoadBalancer lb : lbs) lb.start();
    }

    public void stopAll() {
        for (LoadBalancer lb : lbs) lb.stop();
    }

    public LoadBalancer getLBForPacket(FiveTuple tuple) {
        int hash = tuple.hashCode();
        int lbIndex = Math.abs(hash) % lbs.size();
        return lbs.get(lbIndex);
    }

    public LoadBalancer getLB(int id) { return lbs.get(id); }
    public int getNumLBs() { return lbs.size(); }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats stats = new AggregatedStats();
        for (LoadBalancer lb : lbs) {
            LoadBalancer.LBStats lbStats = lb.getStats();
            stats.totalReceived += lbStats.packetsReceived;
            stats.totalDispatched += lbStats.packetsDispatched;
        }
        return stats;
    }

    public static class AggregatedStats {
        public long totalReceived;
        public long totalDispatched;
    }
}
