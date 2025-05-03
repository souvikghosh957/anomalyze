package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;
import com.threat.anomalyze.commons.util.EntropyUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.Frequency;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
public class SSHFeatureExtractor extends BaseFeatureExtractor implements IFeatureExtractor {

    // Define weak algorithms for security analysis
    private static final Set<String> WEAK_ALGORITHMS = Set.of(
            "arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "des-cbc",
            "hmac-md5", "hmac-md5-96", "hmac-sha1-96", "diffie-hellman-group1-sha1"
    );
    private static final int STANDARD_SSH_PORT = 22;

    public SSHFeatureExtractor(FeatureAggregator aggregator) {
        super(aggregator, FeatureConfig.WINDOW_SIZE_MS);
    }

    @Override
    public void extractFeatures(String ip, long windowStart, Map<String, List<JsonNode>> logEntriesByType) {
        // Retrieve SSH log entries
        List<JsonNode> sshEntries = logEntriesByType.getOrDefault("ssh", Collections.emptyList());
        if (sshEntries.isEmpty()) {
            log.debug("No SSH entries for IP: {} in window: {}", ip, windowStart);
            return;
        }

        // Retrieve conn.log entries for correlation
        List<JsonNode> connEntries = logEntriesByType.getOrDefault("conn", Collections.emptyList());
        if (connEntries.isEmpty()) {
            log.warn("No conn.log entries available for IP: {} in window: {}. Duration and byte features will be zero.", ip, windowStart);
        }

        // Build conn.log UID map for efficient lookup
        Map<String, JsonNode> uidToConn = connEntries.stream()
                .collect(Collectors.toMap(
                        conn -> conn.path("uid").asText(""),
                        conn -> conn,
                        (c1, c2) -> c1 // Keep first entry in case of duplicates
                ));

        // Separate inbound and outbound connections
        List<JsonNode> outboundEntries = sshEntries.stream()
                .filter(e -> ip.equals(e.path("id.orig_h").asText("")))
                .toList();
        List<JsonNode> inboundEntries = sshEntries.stream()
                .filter(e -> ip.equals(e.path("id.resp_h").asText("")))
                .toList();

        // **Outbound Features**
        // Feature 1: Number of outgoing SSH connections
        int outgoingConnCount = outboundEntries.size();

        // Feature 2: Number of unique destination IPs
        Set<String> uniqueDestIps = outboundEntries.stream()
                .map(e -> e.path("id.resp_h").asText(""))
                .filter(destIp -> !destIp.isEmpty())
                .collect(Collectors.toSet());
        int uniqueDestIpCount = uniqueDestIps.size();

        // Feature 3: Outbound authentication success ratio
        long outboundSuccessAuthCount = outboundEntries.stream()
                .filter(e -> e.path("auth_success").asBoolean(false))
                .count();
        double outboundAuthSuccessRatio = outgoingConnCount > 0 ? (double) outboundSuccessAuthCount / outgoingConnCount : 0.0;

        // Feature 4: Entropy of server software (outbound)
        Frequency serverFreq = new Frequency();
        outboundEntries.forEach(e -> {
            String server = e.path("server").asText("");
            if (!server.isEmpty()) serverFreq.addValue(server);
        });
        double serverEntropy = EntropyUtils.calculateEntropy(serverFreq);

        // Feature 5: Number of outbound connections using weak algorithms
        long outboundWeakAlgoCount = outboundEntries.stream()
                .filter(e -> WEAK_ALGORITHMS.contains(e.path("cipher_alg").asText("").toLowerCase()) ||
                        WEAK_ALGORITHMS.contains(e.path("mac_alg").asText("").toLowerCase()) ||
                        WEAK_ALGORITHMS.contains(e.path("kex_alg").asText("").toLowerCase()))
                .count();

        // Feature 6: Average authentication attempts per outbound connection
        DescriptiveStatistics outboundAuthAttemptsStats = new DescriptiveStatistics();
        outboundEntries.forEach(e -> {
            int attempts = e.path("auth_attempts").asInt(0);
            // Handle Zeek bug: if auth_success is false and attempts is 0, assume 1 attempt
            if (!e.path("auth_success").asBoolean(false) && attempts == 0) {
                attempts = 1;
            }
            outboundAuthAttemptsStats.addValue(attempts);
        });
        double outboundAvgAuthAttempts = outboundAuthAttemptsStats.getN() > 0 ? outboundAuthAttemptsStats.getMean() : 0.0;

        // Feature 7: Number of unique destination ports (outbound)
        Set<Integer> uniqueDestPorts = outboundEntries.stream()
                .map(e -> e.path("id.resp_p").asInt(0))
                .filter(port -> port > 0)
                .collect(Collectors.toSet());
        int uniqueDestPortCount = uniqueDestPorts.size();

        // Feature 8: Number of outbound connections to non-standard ports
        long nonStandardPortCount = outboundEntries.stream()
                .filter(e -> e.path("id.resp_p").asInt(0) != STANDARD_SSH_PORT)
                .count();

        // Feature 9: Timestamp variance (outbound)
        DescriptiveStatistics outboundTsStats = new DescriptiveStatistics();
        outboundEntries.forEach(e -> {
            double ts = e.path("ts").asDouble(0.0);
            if (ts > 0) outboundTsStats.addValue(ts);
        });
        double outboundTsVariance = outboundTsStats.getN() > 0 ? outboundTsStats.getVariance() : 0.0;

        // Feature 10: Average session duration (outbound, from conn.log)
        DescriptiveStatistics outboundDurationStats = new DescriptiveStatistics();
        for (JsonNode sshEntry : outboundEntries) {
            String uid = sshEntry.path("uid").asText("");
            JsonNode conn = uidToConn.get(uid);
            if (conn != null) {
                double duration = conn.path("duration").asDouble(0.0);
                outboundDurationStats.addValue(duration);
            }
        }
        double outboundAvgDuration = outboundDurationStats.getN() > 0 ? outboundDurationStats.getMean() : 0.0;

        // Feature 11: Total bytes transferred (outbound, from conn.log)
        double outboundTotalBytes = 0.0;
        for (JsonNode sshEntry : outboundEntries) {
            String uid = sshEntry.path("uid").asText("");
            JsonNode conn = uidToConn.get(uid);
            if (conn != null) {
                double origBytes = conn.path("orig_bytes").asDouble(0.0);
                double respBytes = conn.path("resp_bytes").asDouble(0.0);
                outboundTotalBytes += origBytes + respBytes;
            }
        }

        // Feature 12: Entropy of cipher algorithms (outbound)
        Frequency outboundCipherFreq = new Frequency();
        outboundEntries.forEach(e -> {
            String cipher = e.path("cipher_alg").asText("");
            if (!cipher.isEmpty()) outboundCipherFreq.addValue(cipher);
        });
        double outboundCipherEntropy = EntropyUtils.calculateEntropy(outboundCipherFreq);

        // Feature 13: Entropy of HASSH fingerprints (outbound clients)
        Frequency hasshFreq = new Frequency();
        outboundEntries.forEach(e -> {
            String hassh = e.path("hassh").asText("");
            if (!hassh.isEmpty()) hasshFreq.addValue(hassh);
        });
        double hasshEntropy = EntropyUtils.calculateEntropy(hasshFreq);

        // **Inbound Features**
        // Feature 14: Number of inbound SSH connections
        int inboundConnCount = inboundEntries.size();

        // Feature 15: Number of unique source IPs
        Set<String> uniqueSrcIps = inboundEntries.stream()
                .map(e -> e.path("id.orig_h").asText(""))
                .filter(srcIp -> !srcIp.isEmpty())
                .collect(Collectors.toSet());
        int uniqueSrcIpCount = uniqueSrcIps.size();

        // Feature 16: Inbound authentication success ratio
        long inboundSuccessAuthCount = inboundEntries.stream()
                .filter(e -> e.path("auth_success").asBoolean(false))
                .count();
        double inboundAuthSuccessRatio = inboundConnCount > 0 ? (double) inboundSuccessAuthCount / inboundConnCount : 0.0;

        // Feature 17: Entropy of client software (inbound)
        Frequency clientFreq = new Frequency();
        inboundEntries.forEach(e -> {
            String client = e.path("client").asText("");
            if (!client.isEmpty()) clientFreq.addValue(client);
        });
        double clientEntropy = EntropyUtils.calculateEntropy(clientFreq);

        // Feature 18: Number of inbound connections using weak algorithms
        long inboundWeakAlgoCount = inboundEntries.stream()
                .filter(e -> WEAK_ALGORITHMS.contains(e.path("cipher_alg").asText("").toLowerCase()) ||
                        WEAK_ALGORITHMS.contains(e.path("mac_alg").asText("").toLowerCase()) ||
                        WEAK_ALGORITHMS.contains(e.path("kex_alg").asText("").toLowerCase()))
                .count();

        // Feature 19: Average authentication attempts per inbound connection
        DescriptiveStatistics inboundAuthAttemptsStats = new DescriptiveStatistics();
        inboundEntries.forEach(e -> {
            int attempts = e.path("auth_attempts").asInt(0);
            if (!e.path("auth_success").asBoolean(false) && attempts == 0) {
                attempts = 1;
            }
            inboundAuthAttemptsStats.addValue(attempts);
        });
        double inboundAvgAuthAttempts = inboundAuthAttemptsStats.getN() > 0 ? inboundAuthAttemptsStats.getMean() : 0.0;

        // Feature 20: Entropy of HASSH server fingerprints (inbound servers)
        Frequency hasshServerFreq = new Frequency();
        inboundEntries.forEach(e -> {
            String hasshServer = e.path("hasshServer").asText("");
            if (!hasshServer.isEmpty()) hasshServerFreq.addValue(hasshServer);
        });
        double hasshServerEntropy = EntropyUtils.calculateEntropy(hasshServerFreq);

        // Feature 21: Number of connections without client identification
        long noClientIdCount = inboundEntries.stream()
                .filter(e -> e.path("client").asText("").isEmpty())
                .count();

        // Submit features to aggregator
        Map<String, Double> features = new HashMap<>();
        features.put(FeatureConfig.SSH_OUTGOING_CONNECTIONS, (double) outgoingConnCount);
        features.put(FeatureConfig.SSH_UNIQUE_DEST_IPS, (double) uniqueDestIpCount);
        features.put(FeatureConfig.SSH_AUTH_SUCCESS_RATIO, outboundAuthSuccessRatio);
        features.put(FeatureConfig.SSH_SERVER_SOFTWARE_ENTROPY, serverEntropy);
        features.put(FeatureConfig.SSH_WEAK_ALGO_COUNT, (double) outboundWeakAlgoCount);
        features.put(FeatureConfig.SSH_AVG_AUTH_ATTEMPTS, outboundAvgAuthAttempts);
        features.put(FeatureConfig.SSH_UNIQUE_DEST_PORTS, (double) uniqueDestPortCount);
        features.put(FeatureConfig.SSH_NON_STANDARD_PORT_COUNT, (double) nonStandardPortCount);
        features.put(FeatureConfig.SSH_TIMESTAMP_VARIANCE, outboundTsVariance);
        features.put(FeatureConfig.SSH_AVG_DURATION, outboundAvgDuration);
        features.put(FeatureConfig.SSH_TOTAL_BYTES, outboundTotalBytes);
        features.put(FeatureConfig.SSH_CIPHER_ALGO_ENTROPY, outboundCipherEntropy);
        features.put(FeatureConfig.SSH_HASSH_ENTROPY, hasshEntropy);
        features.put(FeatureConfig.SSH_INBOUND_CONNECTIONS, (double) inboundConnCount);
        features.put(FeatureConfig.SSH_UNIQUE_SRC_IPS, (double) uniqueSrcIpCount);
        features.put(FeatureConfig.SSH_INBOUND_AUTH_SUCCESS_RATIO, inboundAuthSuccessRatio);
        features.put(FeatureConfig.SSH_CLIENT_SOFTWARE_ENTROPY, clientEntropy);
        features.put(FeatureConfig.SSH_INBOUND_WEAK_ALGO_COUNT, (double) inboundWeakAlgoCount);
        features.put(FeatureConfig.SSH_INBOUND_AVG_AUTH_ATTEMPTS, inboundAvgAuthAttempts);
        features.put(FeatureConfig.SSH_HASSH_SERVER_ENTROPY, hasshServerEntropy);
        features.put(FeatureConfig.SSH_NO_CLIENT_ID_COUNT, (double) noClientIdCount);

        submitFeatures(ip, windowStart, features);
    }
}