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

@Service
@Slf4j
public class HttpFeatureExtractor extends BaseFeatureExtractor implements IFeatureExtractor {

    private static final Set<String> COMMON_METHODS = Set.of("GET", "POST", "HEAD");
    private static final Set<String> SUSPICIOUS_URI_PATTERNS = Set.of("..", "%00", "'", "--", ";", "&", "|", "%25", "%2e");

    public HttpFeatureExtractor(FeatureAggregator aggregator) {
        super(aggregator, FeatureConfig.WINDOW_SIZE_MS);
    }

    @Override
    public void extractFeatures(String ip, long windowStart, Map<String, List<JsonNode>> logEntriesByType) {
        List<JsonNode> httpEntries = logEntriesByType.get("http");
        if (httpEntries == null || httpEntries.isEmpty()) {
            log.debug("No http entries for IP: {} in window: {}", ip, windowStart);
            return;
        }

        // Rare HTTP methods
        long rareMethodCount = httpEntries.stream()
                .map(e -> e.path("method").asText(""))
                .filter(method -> !COMMON_METHODS.contains(method))
                .count();

        // URI anomalies (expanded)
        long uriAnomalyCount = httpEntries.stream()
                .map(e -> e.path("uri").asText(""))
                .filter(uri -> SUSPICIOUS_URI_PATTERNS.stream().anyMatch(uri::contains))
                .count();

        // Status code ratios (split into 4xx and 5xx)
        long clientErrorCount = httpEntries.stream()
                .map(e -> e.path("status_code").asInt(0))
                .filter(code -> code >= 400 && code < 500)
                .count();
        long serverErrorCount = httpEntries.stream()
                .map(e -> e.path("status_code").asInt(0))
                .filter(code -> code >= 500 && code < 600)
                .count();
        double clientErrorRatio = httpEntries.isEmpty() ? 0.0 : (double) clientErrorCount / httpEntries.size();
        double serverErrorRatio = httpEntries.isEmpty() ? 0.0 : (double) serverErrorCount / httpEntries.size();

        // Method entropy (replacing skew)
        Frequency methodFreq = new Frequency();
        httpEntries.forEach(e -> methodFreq.addValue(e.path("method").asText("")));
        double methodEntropy = EntropyUtils.calculateEntropy(methodFreq);

        // User-agent entropy
        Frequency uaFreq = new Frequency();
        httpEntries.forEach(e -> uaFreq.addValue(e.path("user_agent").asText("")));
        double uaEntropy = EntropyUtils.calculateEntropy(uaFreq);

        // Request body length variance
        DescriptiveStatistics bodyLenStats = new DescriptiveStatistics();
        httpEntries.forEach(e -> bodyLenStats.addValue(e.path("request_body_len").asDouble(0.0)));
        double bodyLenVariance = bodyLenStats.getVariance();

        // Header anomalies (e.g., X-Forwarded-For)
        long headerAnomalyCount = httpEntries.stream()
                .filter(e -> e.has("request_headers") &&
                        e.get("request_headers").toString().contains("X-Forwarded-For"))
                .count();

        // Submit features
        Map<String, Double> features = Map.of(
                FeatureConfig.RARE_HTTP_METHODS, (double) rareMethodCount,
                FeatureConfig.URI_ANOMALIES, (double) uriAnomalyCount,
                FeatureConfig.CLIENT_ERROR_RATIO, clientErrorRatio,
                FeatureConfig.SERVER_ERROR_RATIO, serverErrorRatio,
                FeatureConfig.METHOD_ENTROPY, methodEntropy,
                FeatureConfig.USER_AGENT_ENTROPY, uaEntropy,
                FeatureConfig.BODY_LENGTH_ENTROPY, bodyLenVariance,
                FeatureConfig.HEADER_ANOMALY_COUNT, (double) headerAnomalyCount
        );
        submitFeatures(ip, windowStart, features);
    }
}