package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.Frequency;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
public class ConnFeatureExtractor extends BaseFeatureExtractor {
    public ConnFeatureExtractor(FeatureAggregator aggregator) {
        super(aggregator);
    }

    public void process(List<JsonNode> entries) {
        entries.forEach(entry -> {
            String ip = entry.get("id.orig_h").asText();
            long timestamp = (long) (entry.get("ts").asDouble() * 1000);

            Map<String, Double> features = new HashMap<>();
            features.put("conn_freq", 1.0); // Count will be summed in aggregator

            // Calculate other features
            String port = entry.get("id.resp_p").asText();
            double duration = entry.get("duration").asDouble();

            submitFeatures(ip, timestamp, Map.of(
                    "unique_ports", 1.0,
                    "conn_duration_total", duration,
                    "port_count_" + port, 1.0
            ));
        });
    }

    // Called periodically to finalize window calculations
    public void finalizeWindow(String ip, long windowStart, List<JsonNode> entries) {
        int connFreq = entries.size();
        Set<String> ports = entries.stream()
                .map(e -> e.get("id.resp_p").asText())
                .collect(Collectors.toSet());

        double totalDuration = entries.stream()
                .mapToDouble(e -> e.get("duration").asDouble())
                .sum();

        Frequency freq = new Frequency();
        entries.forEach(e -> freq.addValue(e.get("id.resp_p").asText()));

        aggregator.addFeatures(ip, windowStart, Map.of(
                "conn_freq", (double) connFreq,
                "unique_ports", (double) ports.size(),
                "conn_duration_avg", connFreq > 0 ? totalDuration / connFreq : 0.0,
                "port_entropy", 0.0 //TODO: fix this
        ));
    }
}
