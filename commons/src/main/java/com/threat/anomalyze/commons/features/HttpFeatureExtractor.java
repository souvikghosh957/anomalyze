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
    private static final Set<String> SUSPICIOUS_URI_PATTERNS = Set.of(
            "..", "%00", "'", "--", ";", "&", "|", "%25", "%2e", "%252e", "%3b", "%27"
    );

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
                .filter(method -> !method.isEmpty() && !COMMON_METHODS.contains(method))
                .count();

        // URI anomalies
        long uriAnomalyCount = httpEntries.stream()
                .map(e -> e.path("uri").asText("").toLowerCase())
                .filter(uri -> !uri.isEmpty() && SUSPICIOUS_URI_PATTERNS.stream().anyMatch(uri::contains))
                .count();

        // URI length variance
        DescriptiveStatistics uriLenStats = new DescriptiveStatistics();
        httpEntries.forEach(e -> {
            String uri = e.path("uri").asText("");
            if (!uri.isEmpty()) uriLenStats.addValue(uri.length());
        });
        double uriLenVariance = uriLenStats.getN() > 0 ? uriLenStats.getVariance() : 0.0;

        // Status code ratios
        long clientErrorCount = httpEntries.stream()
                .map(e -> e.path("status_code").asInt(0))
                .filter(code -> code >= 400 && code < 500)
                .count();
        long serverErrorCount = httpEntries.stream()
                .map(e -> e.path("status_code").asInt(0))
                .filter(code -> code >= 500 && code < 600)
                .count();
        long authErrorCount = httpEntries.stream()
                .map(e -> e.path("status_code").asInt(0))
                .filter(code -> code == 401 || code == 403)
                .count();
        double clientErrorRatio = httpEntries.isEmpty() ? 0.0 : (double) clientErrorCount / httpEntries.size();
        double serverErrorRatio = httpEntries.isEmpty() ? 0.0 : (double) serverErrorCount / httpEntries.size();
        double authErrorRatio = httpEntries.isEmpty() ? 0.0 : (double) authErrorCount / httpEntries.size();

        // Method entropy
        Frequency methodFreq = new Frequency();
        httpEntries.forEach(e -> {
            String method = e.path("method").asText("");
            if (!method.isEmpty()) methodFreq.addValue(method);
        });
        double methodEntropy = EntropyUtils.calculateEntropy(methodFreq);

        // User-agent entropy
        Frequency uaFreq = new Frequency();
        httpEntries.forEach(e -> {
            String ua = e.path("user_agent").asText("");
            if (!ua.isEmpty()) uaFreq.addValue(ua);
        });
        double uaEntropy = EntropyUtils.calculateEntropy(uaFreq);

        // Request body length variance
        DescriptiveStatistics bodyLenStats = new DescriptiveStatistics();
        httpEntries.forEach(e -> {
            double len = e.path("request_body_len").asDouble(-1.0);
            if (len >= 0) bodyLenStats.addValue(len);
        });
        double bodyLenVariance = bodyLenStats.getN() > 0 ? bodyLenStats.getVariance() : 0.0;

        // Host entropy
        Frequency hostFreq = new Frequency();
        httpEntries.forEach(e -> {
            String host = e.path("host").asText("");
            if (!host.isEmpty()) hostFreq.addValue(host);
        });
        double hostEntropy = EntropyUtils.calculateEntropy(hostFreq);

        // Temporal clustering
        DescriptiveStatistics tsStats = new DescriptiveStatistics();
        httpEntries.forEach(e -> {
            double ts = e.path("ts").asDouble(-1.0);
            if (ts >= 0) tsStats.addValue(ts);
        });
        double tsVariance = tsStats.getN() > 0 ? tsStats.getVariance() : 0.0;

        Map<String, Double> features = Map.ofEntries(
                Map.entry(FeatureConfig.RARE_HTTP_METHODS, (double) rareMethodCount),
                Map.entry(FeatureConfig.URI_ANOMALIES, (double) uriAnomalyCount),
                Map.entry(FeatureConfig.URI_LENGTH_VARIANCE, uriLenVariance),
                Map.entry(FeatureConfig.CLIENT_ERROR_RATIO, clientErrorRatio),
                Map.entry(FeatureConfig.SERVER_ERROR_RATIO, serverErrorRatio),
                Map.entry(FeatureConfig.AUTH_ERROR_RATIO, authErrorRatio),
                Map.entry(FeatureConfig.METHOD_ENTROPY, methodEntropy),
                Map.entry(FeatureConfig.USER_AGENT_ENTROPY, uaEntropy),
                Map.entry(FeatureConfig.BODY_LENGTH_VARIANCE, bodyLenVariance),
                Map.entry(FeatureConfig.HOST_ENTROPY, hostEntropy),
                Map.entry(FeatureConfig.HTTP_TIMESTAMP_VARIANCE, tsVariance)
        );

        submitFeatures(ip, windowStart, features);
    }
}