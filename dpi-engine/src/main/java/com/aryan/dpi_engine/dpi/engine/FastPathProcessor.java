package com.aryan.dpi_engine.dpi.engine;

import com.aryan.dpi_engine.dpi.inspection.DnsQueryExtractor;
import com.aryan.dpi_engine.dpi.inspection.HttpHostExtractor;
import com.aryan.dpi_engine.dpi.inspection.TlsSniExtractor;
import com.aryan.dpi_engine.dpi.model.AppClassifier;
import com.aryan.dpi_engine.dpi.model.AppType;
import com.aryan.dpi_engine.model.*;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * Fast Path Processor Thread.
 * Each FP thread: connection tracking, DPI, rule matching, forwarding/dropping.
 */
public class FastPathProcessor {
    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final BiConsumer<PacketJob, PacketAction> outputCallback;

    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong packetsForwarded = new AtomicLong(0);
    private final AtomicLong packetsDropped = new AtomicLong(0);
    private final AtomicLong sniExtractions = new AtomicLong(0);
    private final AtomicLong classificationHits = new AtomicLong(0);

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    public FastPathProcessor(int fpId, RuleManager ruleManager,
                             BiConsumer<PacketJob, PacketAction> outputCallback) {
        this.fpId = fpId;
        this.inputQueue = new ThreadSafeQueue<>(10000);
        this.connTracker = new ConnectionTracker(fpId);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    public void start() {
        if (running.get()) return;
        running.set(true);
        thread = new Thread(this::run, "FP-" + fpId);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running.get()) return;
        running.set(false);
        inputQueue.shutdown();
        if (thread != null) {
            try { thread.join(); } catch (InterruptedException ignored) {}
        }
        System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
    }

    private void run() {
        while (running.get()) {
            PacketJob job = inputQueue.popWithTimeout(100);
            if (job == null) {
                connTracker.cleanupStale(300);
                continue;
            }
            packetsProcessed.incrementAndGet();
            PacketAction action = processPacket(job);
            if (outputCallback != null) {
                outputCallback.accept(job, action);
            }
            if (action == PacketAction.DROP) {
                packetsDropped.incrementAndGet();
            } else {
                packetsForwarded.incrementAndGet();
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreateConnection(job.tuple);
        if (conn == null) return PacketAction.FORWARD;

        boolean isOutbound = true;
        connTracker.updateConnection(conn, job.data.length, isOutbound);

        if (job.tuple.protocol == 6) { // TCP
            updateTCPState(conn, job.tcpFlags);
        }

        if (conn.state == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }

        if (conn.state != ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }

        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payloadLength == 0 || job.payloadOffset >= job.data.length) return;

        if (tryExtractSNI(job, conn)) return;
        if (tryExtractHTTPHost(job, conn)) return;

        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            String domain = DnsQueryExtractor.extractQuery(job.data, job.payloadOffset, job.payloadLength);
            if (domain != null) {
                connTracker.classifyConnection(conn, AppType.DNS, domain);
                return;
            }
        }

        if (job.tuple.dstPort == 80) {
            connTracker.classifyConnection(conn, AppType.HTTP, "");
        } else if (job.tuple.dstPort == 443) {
            connTracker.classifyConnection(conn, AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSNI(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 443 && job.payloadLength < 50) return false;
        if (job.payloadOffset >= job.data.length || job.payloadLength == 0) return false;

        String sni = TlsSniExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (sni != null) {
            sniExtractions.incrementAndGet();
            AppType app = AppClassifier.classifyBySni(sni);
            connTracker.classifyConnection(conn, app, sni);
            if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private boolean tryExtractHTTPHost(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 80) return false;
        if (job.payloadOffset >= job.data.length || job.payloadLength == 0) return false;

        String host = HttpHostExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (host != null) {
            AppType app = AppClassifier.classifyBySni(host);
            connTracker.classifyConnection(conn, app, host);
            if (app != AppType.UNKNOWN && app != AppType.HTTP) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) return PacketAction.FORWARD;

        RuleManager.BlockReason blockReason = ruleManager.shouldBlock(
            job.tuple.srcIp, job.tuple.dstPort, conn.appType, conn.sni);

        if (blockReason != null) {
            StringBuilder ss = new StringBuilder();
            ss.append("[FP").append(fpId).append("] BLOCKED packet: ");
            switch (blockReason.type) {
                case IP: ss.append("IP ").append(blockReason.detail); break;
                case APP: ss.append("App ").append(blockReason.detail); break;
                case DOMAIN: ss.append("Domain ").append(blockReason.detail); break;
                case PORT: ss.append("Port ").append(blockReason.detail); break;
            }
            System.out.println(ss.toString());
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }
        return PacketAction.FORWARD;
    }

    private void updateTCPState(Connection conn, int tcpFlags) {
        final int SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04;

        if ((tcpFlags & SYN) != 0) {
            if ((tcpFlags & ACK) != 0) { conn.synAckSeen = true; }
            else { conn.synSeen = true; }
        }
        if (conn.synSeen && conn.synAckSeen && (tcpFlags & ACK) != 0) {
            if (conn.state == ConnectionState.NEW) { conn.state = ConnectionState.ESTABLISHED; }
        }
        if ((tcpFlags & FIN) != 0) { conn.finSeen = true; }
        if ((tcpFlags & RST) != 0) { conn.state = ConnectionState.CLOSED; }
        if (conn.finSeen && (tcpFlags & ACK) != 0) { conn.state = ConnectionState.CLOSED; }
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() { return inputQueue; }
    public ConnectionTracker getConnectionTracker() { return connTracker; }
    public int getId() { return fpId; }
    public boolean isRunning() { return running.get(); }

    public FPStats getStats() {
        FPStats stats = new FPStats();
        stats.packetsProcessed = packetsProcessed.get();
        stats.packetsForwarded = packetsForwarded.get();
        stats.packetsDropped = packetsDropped.get();
        stats.connectionsTracked = connTracker.getActiveCount();
        stats.sniExtractions = sniExtractions.get();
        stats.classificationHits = classificationHits.get();
        return stats;
    }

    public static class FPStats {
        public long packetsProcessed;
        public long packetsForwarded;
        public long packetsDropped;
        public long connectionsTracked;
        public long sniExtractions;
        public long classificationHits;
    }
}
