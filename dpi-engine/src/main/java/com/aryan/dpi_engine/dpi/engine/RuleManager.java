package com.aryan.dpi_engine.dpi.engine;


import com.aryan.dpi_engine.dpi.model.AppType;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Rule Manager - Manages blocking/filtering rules.
 * Thread-safe for concurrent access from FP threads.
 */
public class RuleManager {
    // Thread-safe containers with read-write locks
    private final ReentrantReadWriteLock ipLock = new ReentrantReadWriteLock();
    private final Set<Long> blockedIps = new HashSet<>();

    private final ReentrantReadWriteLock appLock = new ReentrantReadWriteLock();
    private final Set<AppType> blockedApps = new HashSet<>();

    private final ReentrantReadWriteLock domainLock = new ReentrantReadWriteLock();
    private final Set<String> blockedDomains = new HashSet<>();
    private final List<String> domainPatterns = new ArrayList<>();

    private final ReentrantReadWriteLock portLock = new ReentrantReadWriteLock();
    private final Set<Integer> blockedPorts = new HashSet<>();

    // ========== IP Blocking ==========

    public void blockIP(long ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.add(ip);
        } finally {
            ipLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked IP: " + ipToString(ip));
    }

    public void blockIP(String ip) {
        blockIP(parseIP(ip));
    }

    public void unblockIP(long ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.remove(ip);
        } finally {
            ipLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Unblocked IP: " + ipToString(ip));
    }

    public void unblockIP(String ip) {
        unblockIP(parseIP(ip));
    }

    public boolean isIPBlocked(long ip) {
        ipLock.readLock().lock();
        try {
            return blockedIps.contains(ip);
        } finally {
            ipLock.readLock().unlock();
        }
    }

    public List<String> getBlockedIPs() {
        ipLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>();
            for (long ip : blockedIps) {
                result.add(ipToString(ip));
            }
            return result;
        } finally {
            ipLock.readLock().unlock();
        }
    }

    // ========== Application Blocking ==========

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.add(app);
        } finally {
            appLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked app: " + AppType.toString(app));
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.remove(app);
        } finally {
            appLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Unblocked app: " + AppType.toString(app));
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            appLock.readLock().unlock();
        }
    }

    public List<AppType> getBlockedApps() {
        appLock.readLock().lock();
        try {
            return new ArrayList<>(blockedApps);
        } finally {
            appLock.readLock().unlock();
        }
    }

    // ========== Domain Blocking ==========

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.add(domain);
            } else {
                blockedDomains.add(domain);
            }
        } finally {
            domainLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked domain: " + domain);
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.remove(domain);
            } else {
                blockedDomains.remove(domain);
            }
        } finally {
            domainLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Unblocked domain: " + domain);
    }

    public boolean isDomainBlocked(String domain) {
        domainLock.readLock().lock();
        try {
            // Check exact match
            if (blockedDomains.contains(domain)) {
                return true;
            }

            // Check patterns
            String lowerDomain = domain.toLowerCase();
            for (String pattern : domainPatterns) {
                if (domainMatchesPattern(lowerDomain, pattern.toLowerCase())) {
                    return true;
                }
            }

            return false;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        domainLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedDomains);
            result.addAll(domainPatterns);
            return result;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    // ========== Port Blocking ==========

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.add(port);
        } finally {
            portLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked port: " + port);
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.remove(port);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try {
            return blockedPorts.contains(port);
        } finally {
            portLock.readLock().unlock();
        }
    }

    // ========== Combined Check ==========

    public BlockReason shouldBlock(long srcIp, int dstPort, AppType app, String domain) {
        // Check IP first (most specific)
        if (isIPBlocked(srcIp)) {
            return new BlockReason(BlockReason.Type.IP, ipToString(srcIp));
        }

        // Check port
        if (isPortBlocked(dstPort)) {
            return new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort));
        }

        // Check app
        if (isAppBlocked(app)) {
            return new BlockReason(BlockReason.Type.APP, AppType.toString(app));
        }

        // Check domain
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return new BlockReason(BlockReason.Type.DOMAIN, domain);
        }

        return null;
    }

    // ========== Rule Persistence ==========

    public boolean saveRules(String filename) {
        try (PrintWriter file = new PrintWriter(new FileWriter(filename))) {
            // Save blocked IPs
            file.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIPs()) {
                file.println(ip);
            }

            // Save blocked apps
            file.println("\n[BLOCKED_APPS]");
            for (AppType app : getBlockedApps()) {
                file.println(AppType.toString(app));
            }

            // Save blocked domains
            file.println("\n[BLOCKED_DOMAINS]");
            for (String domain : getBlockedDomains()) {
                file.println(domain);
            }

            // Save blocked ports
            file.println("\n[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try {
                for (int port : blockedPorts) {
                    file.println(port);
                }
            } finally {
                portLock.readLock().unlock();
            }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader file = new BufferedReader(new FileReader(filename))) {
            String line;
            String currentSection = "";

            while ((line = file.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;

                if (line.startsWith("[")) {
                    currentSection = line;
                    continue;
                }

                switch (currentSection) {
                    case "[BLOCKED_IPS]":
                        blockIP(line);
                        break;
                    case "[BLOCKED_APPS]":
                        for (AppType app : AppType.values()) {
                            if (AppType.toString(app).equals(line)) {
                                blockApp(app);
                                break;
                            }
                        }
                        break;
                    case "[BLOCKED_DOMAINS]":
                        blockDomain(line);
                        break;
                    case "[BLOCKED_PORTS]":
                        blockPort(Integer.parseInt(line));
                        break;
                }
            }

            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();
        try { blockedIps.clear(); } finally { ipLock.writeLock().unlock(); }

        appLock.writeLock().lock();
        try { blockedApps.clear(); } finally { appLock.writeLock().unlock(); }

        domainLock.writeLock().lock();
        try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainLock.writeLock().unlock(); }

        portLock.writeLock().lock();
        try { blockedPorts.clear(); } finally { portLock.writeLock().unlock(); }

        System.out.println("[RuleManager] All rules cleared");
    }

    public RuleStats getStats() {
        RuleStats stats = new RuleStats();
        ipLock.readLock().lock();
        try { stats.blockedIps = blockedIps.size(); } finally { ipLock.readLock().unlock(); }
        appLock.readLock().lock();
        try { stats.blockedApps = blockedApps.size(); } finally { appLock.readLock().unlock(); }
        domainLock.readLock().lock();
        try { stats.blockedDomains = blockedDomains.size() + domainPatterns.size(); } finally { domainLock.readLock().unlock(); }
        portLock.readLock().lock();
        try { stats.blockedPorts = blockedPorts.size(); } finally { portLock.readLock().unlock(); }
        return stats;
    }

    // ========== Helpers ==========

    public static long parseIP(String ip) {
        long result = 0;
        int octet = 0;
        int shift = 0;

        for (char c : ip.toCharArray()) {
            if (c == '.') {
                result |= ((long) octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= ((long) octet << shift);

        return result;
    }

    public static String ipToString(long ip) {
        return ((ip >> 0) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.length() >= 2 && pattern.charAt(0) == '*' && pattern.charAt(1) == '.') {
            String suffix = pattern.substring(1); // .example.com

            if (domain.length() >= suffix.length() &&
                domain.substring(domain.length() - suffix.length()).equals(suffix)) {
                return true;
            }

            if (domain.equals(pattern.substring(2))) {
                return true;
            }
        }

        return false;
    }

    public static class BlockReason {
        public enum Type { IP, APP, DOMAIN, PORT }
        public Type type;
        public String detail;

        public BlockReason(Type type, String detail) {
            this.type = type;
            this.detail = detail;
        }
    }

    public static class RuleStats {
        public long blockedIps;
        public long blockedApps;
        public long blockedDomains;
        public long blockedPorts;
    }
}
