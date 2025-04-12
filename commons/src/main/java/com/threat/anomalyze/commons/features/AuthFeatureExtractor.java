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
public class AuthFeatureExtractor extends BaseFeatureExtractor implements IFeatureExtractor {

    public AuthFeatureExtractor(FeatureAggregator aggregator) {
        super(aggregator, FeatureConfig.WINDOW_SIZE_MS);
    }

    @Override
    public void extractFeatures(String ip, long windowStart, Map<String, List<JsonNode>> logEntriesByType) {
        List<JsonNode> authEntries = logEntriesByType.get("auth");
        if (authEntries == null || authEntries.isEmpty()) {
            log.debug("No auth entries for IP: {} in window: {}", ip, windowStart);
            return;
        }

        // Failed login ratio
        long failedCount = authEntries.stream()
                .filter(e -> "fail".equals(e.path("result").asText("")))
                .count();
        double failedRatio = authEntries.isEmpty() ? 0 : (double) failedCount / authEntries.size();

        // Success login ratio (new)
        long successCount = authEntries.stream()
                .filter(e -> "success".equals(e.path("result").asText("")))
                .count();
        double successRatio = authEntries.isEmpty() ? 0 : (double) successCount / authEntries.size();

        // Unique username entropy
        Frequency usernameFreq = new Frequency();
        authEntries.forEach(e -> {
            String username = e.path("username").asText("");
            if (!username.isEmpty()) usernameFreq.addValue(username);
        });
        double usernameEntropy = EntropyUtils.calculateEntropy(usernameFreq);

        // Login attempt rate
        double windowDurationSeconds = (double) FeatureConfig.WINDOW_SIZE_MS / 1000.0;
        double attemptRate = authEntries.size() / windowDurationSeconds;

        // Unique source IP count
        Set<String> uniqueSourceIps = authEntries.stream()
                .map(e -> e.path("source_ip").asText(""))
                .filter(ipVal -> !ipVal.isEmpty())
                .collect(Collectors.toSet());
        long uniqueSourceIpCount = uniqueSourceIps.size();

        // Temporal clustering of failures
        DescriptiveStatistics failedTsStats = new DescriptiveStatistics();
        for (JsonNode entry : authEntries) {
            if ("fail".equals(entry.path("result").asText(""))) {
                double ts = entry.path("ts").asDouble(-1.0);
                if (ts >= 0) failedTsStats.addValue(ts);
            }
        }
        double failedTsVariance = failedTsStats.getN() > 0 ? failedTsStats.getVariance() : 0.0;

        // Submit features (corrected label)
        Map<String, Double> features = Map.of(
                FeatureConfig.FAILED_LOGIN_RATIO, failedRatio,
                FeatureConfig.SUCCESS_LOGIN_RATIO, successRatio,
                FeatureConfig.USERNAME_ENTROPY, usernameEntropy,
                FeatureConfig.ATTEMPT_RATE, attemptRate,
                FeatureConfig.UNIQUE_SOURCE_IP_COUNT, (double) uniqueSourceIpCount,
                FeatureConfig.FAILED_TS_VARIANCE, failedTsVariance
        );
        submitFeatures(ip, windowStart, features);
    }
}