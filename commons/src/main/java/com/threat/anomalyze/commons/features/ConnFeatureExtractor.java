package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;
import com.threat.anomalyze.commons.util.EntropyUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.Frequency;
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

        // Feature: Connection frequency
        int connFreq = connEntries.size();

        // Feature: Unique destination ports
        Set<String> uniquePorts = connEntries.stream()
                .map(e -> e.get("id.resp_p").asText())
                .collect(Collectors.toSet());

        // Feature: Average connection duration
        double totalDuration = connEntries.stream()
                .mapToDouble(e -> e.get("duration").asDouble(0))
                .sum();
        double connDurationAvg = connFreq > 0 ? totalDuration / connFreq : 0.0;

        // Feature: Port entropy
        Frequency portFreq = new Frequency();
        connEntries.forEach(e -> portFreq.addValue(e.get("id.resp_p").asText()));
        double portEntropy = EntropyUtils.calculateEntropy(portFreq);

        // Feature: Connection state entropy
        Frequency stateFreq = new Frequency();
        connEntries.forEach(e -> stateFreq.addValue(e.get("conn_state").asText()));
        double connectionStateEntropy = EntropyUtils.calculateEntropy(stateFreq);

        // Feature: Bytes in/out ratio
        double bytesInOutRatio = connEntries.stream()
                .mapToDouble(e -> {
                    double origBytes = e.get("orig_bytes").asDouble(0);
                    double respBytes = e.get("resp_bytes").asDouble(0);
                    return origBytes / (respBytes + 1);
                })
                .average()
                .orElse(0.0);

        // Feature: Destination IP entropy
        Frequency destIpFreq = new Frequency();
        connEntries.forEach(e -> destIpFreq.addValue(e.get("id.resp_h").asText()));
        double destinationIpEntropy = EntropyUtils.calculateEntropy(destIpFreq);

        // Feature: UDP/TCP ratio
        Map<String, Long> protoCounts = connEntries.stream()
                .collect(Collectors.groupingBy(
                        e -> e.get("proto").asText(),
                        Collectors.counting()
                ));
        long udpCount = protoCounts.getOrDefault("udp", 0L);
        long tcpCount = protoCounts.getOrDefault("tcp", 0L);
        double udpTcpRatio = (double) udpCount / (tcpCount + 1);

        Map<String, Double> features = Map.of(
                FeatureConfig.CONNECTION_FREQUENCY, (double) connFreq,
                FeatureConfig.UNIQUE_PORTS, (double) uniquePorts.size(),
                FeatureConfig.CONNECTION_DURATION_AVG, connDurationAvg,
                FeatureConfig.PORT_ENTROPY, portEntropy,
                FeatureConfig.CONNECTION_STATE_ENTROPY, connectionStateEntropy,
                FeatureConfig.BYTES_IN_OUT_RATIO, bytesInOutRatio,
                FeatureConfig.DESTINATION_IP_ENTROPY, destinationIpEntropy,
                FeatureConfig.UDP_TCP_RATIO, udpTcpRatio
        );
        submitFeatures(ip, windowStart, features);
    }

    // Remove the original process method since it's replaced by extractFeatures
}