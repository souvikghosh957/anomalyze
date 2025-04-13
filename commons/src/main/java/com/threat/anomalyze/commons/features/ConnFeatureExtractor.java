package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;
import com.threat.anomalyze.commons.util.EntropyUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.Frequency;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
public class ConnFeatureExtractor extends BaseFeatureExtractor implements IFeatureExtractor {

    public ConnFeatureExtractor(FeatureAggregator aggregator) {
        super(aggregator, FeatureConfig.WINDOW_SIZE_MS);
    }

    @Override
    public void extractFeatures(String ip, long windowStart, Map<String, List<JsonNode>> logEntriesByType) {
        List<JsonNode> connEntries = logEntriesByType.get("conn");
        if (connEntries == null || connEntries.isEmpty()) {
            log.debug("No conn entries for IP: {} in window: {}", ip, windowStart);
            return;
        }

        // Connection frequency
        int connFreq = connEntries.size();

        // Unique destination ports
        Set<String> uniquePorts = connEntries.stream()
                .map(e -> e.get("id.resp_p").asText())
                .collect(Collectors.toSet());

        // Average connection duration
        double totalDuration = 0.0;
        int durationCount = 0;
        for (JsonNode entry : connEntries) {
            JsonNode durationNode = entry.path("duration");
            if (!durationNode.isMissingNode()) {
                totalDuration += durationNode.asDouble();
                durationCount++;
            }
        }
        double connDurationAvg = durationCount > 0 ? totalDuration / durationCount : 0.0;

        // Port entropy
        Frequency portFreq = new Frequency();
        connEntries.forEach(e -> portFreq.addValue(e.get("id.resp_p").asText()));
        double portEntropy = EntropyUtils.calculateEntropy(portFreq);

        // Connection state entropy
        Frequency stateFreq = new Frequency();
        connEntries.forEach(e -> stateFreq.addValue(e.get("conn_state").asText()));
        double connectionStateEntropy = EntropyUtils.calculateEntropy(stateFreq);

        // Bytes in/out ratio (capped)
        double totalBytesInOutRatio = 0.0;
        int bytesRatioCount = 0;
        for (JsonNode entry : connEntries) {
            JsonNode origBytesNode = entry.path("orig_bytes");
            JsonNode respBytesNode = entry.path("resp_bytes");
            if (!origBytesNode.isMissingNode() && !respBytesNode.isMissingNode()) {
                double origBytes = origBytesNode.asDouble();
                double respBytes = respBytesNode.asDouble();
                double ratio = origBytes / (respBytes + 1);
                totalBytesInOutRatio += Math.min(ratio, 100.0); // Cap at 100
                bytesRatioCount++;
            }
        }
        double bytesInOutRatio = bytesRatioCount > 0 ? totalBytesInOutRatio / bytesRatioCount : 0.0;

        // Destination IP entropy
        Frequency destIpFreq = new Frequency();
        connEntries.forEach(e -> destIpFreq.addValue(e.get("id.resp_h").asText()));
        double destinationIpEntropy = EntropyUtils.calculateEntropy(destIpFreq);

        // Source IP entropy
        Frequency srcIpFreq = new Frequency();
        connEntries.forEach(e -> srcIpFreq.addValue(e.get("id.orig_h").asText()));
        double sourceIpEntropy = EntropyUtils.calculateEntropy(srcIpFreq);

        // Protocol ratios
        Map<String, Long> protoCounts = connEntries.stream()
                .collect(Collectors.groupingBy(e -> e.get("proto").asText(), Collectors.counting()));
        long udpCount = protoCounts.getOrDefault("udp", 0L);
        long tcpCount = protoCounts.getOrDefault("tcp", 0L);
        long icmpCount = protoCounts.getOrDefault("icmp", 0L);
        double totalProtos = (double) (tcpCount + udpCount + icmpCount + 1); // Avoid division by zero
        double udpRatio = udpCount / totalProtos;
        double tcpRatio = tcpCount / totalProtos;
        double icmpRatio = icmpCount / totalProtos;

        // Connection rate
        double windowDurationSeconds = (double) FeatureConfig.WINDOW_SIZE_MS / 1000.0;
        double connectionRate = connFreq / windowDurationSeconds;

        // Incomplete connection ratio
        long incompleteCount = connEntries.stream()
                .filter(e -> Set.of("S0", "S1", "REJ").contains(e.get("conn_state").asText()))
                .count();
        long completeCount = connEntries.stream()
                .filter(e -> "SF".equals(e.get("conn_state").asText()))
                .count();
        double incompleteRatio = (double) incompleteCount / (completeCount + 1);

        // Timestamp variance
        DescriptiveStatistics tsStats = new DescriptiveStatistics();
        connEntries.forEach(e -> {
            double ts = e.path("ts").asDouble(-1.0);
            if (ts >= 0) tsStats.addValue(ts);
        });
        double tsVariance = tsStats.getN() > 0 ? tsStats.getVariance() : 0.0;

        // Submit features
        Map<String, Double> features = Map.ofEntries(
                Map.entry(FeatureConfig.CONNECTION_FREQUENCY, (double) connFreq),
                Map.entry(FeatureConfig.UNIQUE_PORTS, (double) uniquePorts.size()),
                Map.entry(FeatureConfig.CONNECTION_DURATION_AVG, connDurationAvg),
                Map.entry(FeatureConfig.PORT_ENTROPY, portEntropy),
                Map.entry(FeatureConfig.CONNECTION_STATE_ENTROPY, connectionStateEntropy),
                Map.entry(FeatureConfig.BYTES_IN_OUT_RATIO, bytesInOutRatio),
                Map.entry(FeatureConfig.DESTINATION_IP_ENTROPY, destinationIpEntropy),
                Map.entry(FeatureConfig.SOURCE_IP_ENTROPY, sourceIpEntropy),
                Map.entry(FeatureConfig.UDP_RATIO, udpRatio),
                Map.entry(FeatureConfig.TCP_RATIO, tcpRatio),
                Map.entry(FeatureConfig.ICMP_RATIO, icmpRatio),
                Map.entry(FeatureConfig.CONNECTION_RATE, connectionRate),
                Map.entry(FeatureConfig.INCOMPLETE_CONNECTION_RATIO, incompleteRatio),
                Map.entry(FeatureConfig.CONNECTION_TIMESTAMP_VARIANCE, tsVariance)
        );

        submitFeatures(ip, windowStart, features);
    }
}