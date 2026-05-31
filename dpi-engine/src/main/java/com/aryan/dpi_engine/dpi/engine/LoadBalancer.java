package com.aryan.dpi_engine.dpi.engine;


import com.aryan.dpi_engine.model.FiveTuple;
import com.aryan.dpi_engine.model.PacketJob;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Load Balancer Thread
 */
public class LoadBalancer {
    private final int lbId;
    private final int fpStartId;
    private final int numFps;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;

    private final AtomicLong packetsReceived = new AtomicLong(0);
    private final AtomicLong packetsDispatched = new AtomicLong(0);
    private final long[] perFpCounts;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    public LoadBalancer(int lbId, List<ThreadSafeQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.inputQueue = new ThreadSafeQueue<>(10000);
        this.fpQueues = fpQueues;
        this.perFpCounts = new long[fpQueues.size()];
    }

    public void start() {
        if (running.get()) return;
        running.set(true);
        thread = new Thread(this::run, "LB-" + lbId);
        thread.start();
        System.out.println("[LB" + lbId + "] Started (serving FP" +
            fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
    }

    public void stop() {
        if (!running.get()) return;
        running.set(false);
        inputQueue.shutdown();
        if (thread != null) {
            try { thread.join(); } catch (InterruptedException ignored) {}
        }
        System.out.println("[LB" + lbId + "] Stopped");
    }

    private void run() {
        while (running.get()) {
            PacketJob job = inputQueue.popWithTimeout(100);
            if (job == null) continue;

            packetsReceived.incrementAndGet();

            int fpIndex = selectFP(job.tuple);
            fpQueues.get(fpIndex).push(job);

            packetsDispatched.incrementAndGet();
            perFpCounts[fpIndex]++;
        }
    }

    private int selectFP(FiveTuple tuple) {
        int hash = tuple.hashCode();
        return Math.abs(hash) % numFps;
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() { return inputQueue; }
    public int getId() { return lbId; }
    public boolean isRunning() { return running.get(); }

    public LBStats getStats() {
        LBStats stats = new LBStats();
        stats.packetsReceived = packetsReceived.get();
        stats.packetsDispatched = packetsDispatched.get();
        stats.perFpPackets = Arrays.copyOf(perFpCounts, perFpCounts.length);
        return stats;
    }

    public static class LBStats {
        public long packetsReceived;
        public long packetsDispatched;
        public long[] perFpPackets;
    }
}
