package com.aryan.dpi_engine.dpi.engine;


import com.aryan.dpi_engine.dpi.model.AppType;
import com.aryan.dpi_engine.model.*;
import com.aryan.dpi_engine.parser.model.*;
import com.aryan.dpi_engine.parser.service.*;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * DPI Engine - Main orchestrator
 */
public class DPIEngine {
    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10000;
        public String rulesFile = "";
        public boolean verbose = false;
    }

    private final Config config;
    private RuleManager ruleManager;
    private GlobalConnectionTable globalConnTable;
    private FPManager fpManager;
    private LBManager lbManager;

    private ThreadSafeQueue<PacketJob> outputQueue = new ThreadSafeQueue<>(10000);
    private Thread outputThread;
    private DataOutputStream outputFile;
    private final Object outputMutex = new Object();

    private final DPIStats stats = new DPIStats();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean processingComplete = new AtomicBoolean(false);
    private Thread readerThread;

    public DPIEngine(Config config) {
        this.config = config;
        int totalFps = config.numLoadBalancers * config.fpsPerLb;

        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Configuration:                                                ║");
        System.out.printf("║   Load Balancers:    %3d                                       ║\n", config.numLoadBalancers);
        System.out.printf("║   FPs per LB:        %3d                                       ║\n", config.fpsPerLb);
        System.out.printf("║   Total FP threads:  %3d                                       ║\n", totalFps);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    public boolean initialize() {
        ruleManager = new RuleManager();

        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }

        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        fpManager = new FPManager(totalFps, ruleManager, this::handleOutput);
        lbManager = new LBManager(config.numLoadBalancers, config.fpsPerLb, fpManager.getQueuePtrs());

        globalConnTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running.get()) return;
        running.set(true);
        processingComplete.set(false);

        outputThread = new Thread(this::outputThreadFunc, "OutputWriter");
        outputThread.start();
        fpManager.startAll();
        lbManager.startAll();
        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running.get()) return;
        running.set(false);
        if (lbManager != null) lbManager.stopAll();
        if (fpManager != null) fpManager.stopAll();
        outputQueue.shutdown();
        if (outputThread != null) {
            try { outputThread.join(); } catch (InterruptedException ignored) {}
        }
        System.out.println("[DPIEngine] All threads stopped");
    }

    public void waitForCompletion() {
        if (readerThread != null) {
            try { readerThread.join(); } catch (InterruptedException ignored) {}
        }
        try { Thread.sleep(500); } catch (InterruptedException ignored) {}
        processingComplete.set(true);
    }

    public boolean processFile(String inputFilePath, String outputFilePath) {
        System.out.println("\n[DPIEngine] Processing: " + inputFilePath);
        System.out.println("[DPIEngine] Output to:  " + outputFilePath + "\n");

        if (ruleManager == null) {
            if (!initialize()) return false;
        }

        try {
            outputFile = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(outputFilePath)));
        } catch (FileNotFoundException e) {
            System.err.println("[DPIEngine] Error: Cannot open output file");
            return false;
        }

        start();
        readerThread = new Thread(() -> readerThreadFunc(inputFilePath), "PcapReader");
        readerThread.start();
        waitForCompletion();

        try { Thread.sleep(200); } catch (InterruptedException ignored) {}
        stop();

        synchronized (outputMutex) {
            if (outputFile != null) {
                try { outputFile.close(); } catch (IOException ignored) {}
                outputFile = null;
            }
        }

        System.out.print(generateReport());
        System.out.print(fpManager.generateClassificationReport());
        return true;
    }

    private void readerThreadFunc(String inputFilePath) {
        PcapReader reader = new PcapReader();
        if (!reader.open(inputFilePath)) {
            System.err.println("[Reader] Error: Cannot open input file");
            return;
        }

        writeOutputHeader(reader.getGlobalHeader());

        RawPacket raw = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();
        long packetId = 0;

        System.out.println("[Reader] Starting packet processing...");

        while (reader.readNextPacket(raw)) {
            if (!PacketParser.parse(raw, parsed)) continue;
            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

            PacketJob job = createPacketJob(raw, parsed, packetId++);

            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(raw.data.length);

            if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
            else if (parsed.hasUdp) stats.udpPackets.incrementAndGet();

            LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
            lb.getInputQueue().push(job);
        }

        System.out.println("[Reader] Finished reading " + packetId + " packets");
        reader.close();
    }

    private PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, long packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec = raw.header.tsSec;
        job.tsUsec = raw.header.tsUsec;

        job.tuple.srcIp = RuleManager.parseIP(parsed.srcIp);
        job.tuple.dstIp = RuleManager.parseIP(parsed.destIp);
        job.tuple.srcPort = parsed.srcPort;
        job.tuple.dstPort = parsed.destPort;
        job.tuple.protocol = parsed.protocol;

        job.tcpFlags = parsed.tcpFlags;
        job.data = raw.data.clone();

        job.ethOffset = 0;
        job.ipOffset = 14;

        if (job.data.length > 14) {
            int ipIhl = job.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transportOffset = 14 + ipHeaderLen;

            if (parsed.hasTcp && job.data.length > job.transportOffset + 12) {
                int tcpDataOffset = (job.data[job.transportOffset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.payloadOffset = job.transportOffset + tcpHeaderLen;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8;
            }

            if (job.payloadOffset < job.data.length) {
                job.payloadLength = job.data.length - job.payloadOffset;
            }
        }

        return job;
    }

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.isEmpty()) {
            PacketJob job = outputQueue.popWithTimeout(100);
            if (job != null) {
                writeOutputPacket(job);
            }
        }
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        outputQueue.push(job);
    }

    private boolean writeOutputHeader(PcapGlobalHeader header) {
        synchronized (outputMutex) {
            if (outputFile == null) return false;
            try {
                ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
                buf.putInt((int) header.magicNumber);
                buf.putShort((short) header.versionMajor);
                buf.putShort((short) header.versionMinor);
                buf.putInt(header.thiszone);
                buf.putInt((int) header.sigfigs);
                buf.putInt((int) header.snaplen);
                buf.putInt((int) header.network);
                outputFile.write(buf.array());
                return true;
            } catch (IOException e) {
                return false;
            }
        }
    }

    private void writeOutputPacket(PacketJob job) {
        synchronized (outputMutex) {
            if (outputFile == null) return;
            try {
                ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
                buf.putInt((int) job.tsSec);
                buf.putInt((int) job.tsUsec);
                buf.putInt(job.data.length);
                buf.putInt(job.data.length);
                outputFile.write(buf.array());
                outputFile.write(job.data);
            } catch (IOException ignored) {}
        }
    }

    // ========== Rule Management API ==========
    public void blockIP(String ip) { if (ruleManager != null) ruleManager.blockIP(ip); }
    public void unblockIP(String ip) { if (ruleManager != null) ruleManager.unblockIP(ip); }
    public void blockApp(AppType app) { if (ruleManager != null) ruleManager.blockApp(app); }
    public void blockApp(String appName) {
        for (AppType app : AppType.values()) {
            if (AppType.toString(app).equals(appName)) { blockApp(app); return; }
        }
        System.err.println("[DPIEngine] Unknown app: " + appName);
    }
    public void unblockApp(AppType app) { if (ruleManager != null) ruleManager.unblockApp(app); }
    public void unblockApp(String appName) {
        for (AppType app : AppType.values()) {
            if (AppType.toString(app).equals(appName)) { unblockApp(app); return; }
        }
    }
    public void blockDomain(String domain) { if (ruleManager != null) ruleManager.blockDomain(domain); }
    public void unblockDomain(String domain) { if (ruleManager != null) ruleManager.unblockDomain(domain); }
    public boolean loadRules(String filename) { return ruleManager != null && ruleManager.loadRules(filename); }
    public boolean saveRules(String filename) { return ruleManager != null && ruleManager.saveRules(filename); }

    // ========== Reporting ==========
    public String generateReport() {
        StringBuilder ss = new StringBuilder();
        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║                    DPI ENGINE STATISTICS                      ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ PACKET STATISTICS                                             ║\n");
        ss.append(String.format("║   Total Packets:      %12d                        ║\n", stats.totalPackets.get()));
        ss.append(String.format("║   Total Bytes:        %12d                        ║\n", stats.totalBytes.get()));
        ss.append(String.format("║   TCP Packets:        %12d                        ║\n", stats.tcpPackets.get()));
        ss.append(String.format("║   UDP Packets:        %12d                        ║\n", stats.udpPackets.get()));
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ FILTERING STATISTICS                                          ║\n");
        ss.append(String.format("║   Forwarded:          %12d                        ║\n", stats.forwardedPackets.get()));
        ss.append(String.format("║   Dropped/Blocked:    %12d                        ║\n", stats.droppedPackets.get()));

        if (stats.totalPackets.get() > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / stats.totalPackets.get();
            ss.append(String.format("║   Drop Rate:          %11.2f%%                        ║\n", dropRate));
        }

        if (lbManager != null) {
            LBManager.AggregatedStats lbStats = lbManager.getAggregatedStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ LOAD BALANCER STATISTICS                                      ║\n");
            ss.append(String.format("║   LB Received:        %12d                        ║\n", lbStats.totalReceived));
            ss.append(String.format("║   LB Dispatched:      %12d                        ║\n", lbStats.totalDispatched));
        }

        if (fpManager != null) {
            FPManager.AggregatedStats fpStats = fpManager.getAggregatedStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ FAST PATH STATISTICS                                          ║\n");
            ss.append(String.format("║   FP Processed:       %12d                        ║\n", fpStats.totalProcessed));
            ss.append(String.format("║   FP Forwarded:       %12d                        ║\n", fpStats.totalForwarded));
            ss.append(String.format("║   FP Dropped:         %12d                        ║\n", fpStats.totalDropped));
            ss.append(String.format("║   Active Connections: %12d                        ║\n", fpStats.totalConnections));
        }

        if (ruleManager != null) {
            RuleManager.RuleStats ruleStats = ruleManager.getStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ BLOCKING RULES                                                ║\n");
            ss.append(String.format("║   Blocked IPs:        %12d                        ║\n", ruleStats.blockedIps));
            ss.append(String.format("║   Blocked Apps:       %12d                        ║\n", ruleStats.blockedApps));
            ss.append(String.format("║   Blocked Domains:    %12d                        ║\n", ruleStats.blockedDomains));
            ss.append(String.format("║   Blocked Ports:      %12d                        ║\n", ruleStats.blockedPorts));
        }

        ss.append("╚══════════════════════════════════════════════════════════════╝\n");
        return ss.toString();
    }

    public RuleManager getRuleManager() { return ruleManager; }
    public Config getConfig() { return config; }
    public boolean isRunning() { return running.get(); }
    public DPIStats getStats() { return stats; }

    public void printStatus() {
        System.out.println("\n--- Live Status ---");
        System.out.println("Packets: " + stats.totalPackets.get() +
            " | Forwarded: " + stats.forwardedPackets.get() +
            " | Dropped: " + stats.droppedPackets.get());
        if (fpManager != null) {
            System.out.println("Connections: " + fpManager.getAggregatedStats().totalConnections);
        }
    }
}
