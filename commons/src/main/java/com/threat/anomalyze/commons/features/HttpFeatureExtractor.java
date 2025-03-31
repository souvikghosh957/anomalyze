package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.Frequency;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.springframework.stereotype.Service;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@Slf4j
public class HttpFeatureExtractor extends BaseFeatureExtractor implements IFeatureExtractor {

    private static final Set<String> COMMON_METHODS = Set.of("GET", "POST", "HEAD");

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

        // URI anomalies
        long uriAnomalyCount = httpEntries.stream()
                .map(e -> e.path("uri").asText(""))
                .filter(uri -> uri.contains("..") || uri.contains("%00"))
                .count();

        // Status code ratio (4xx, 5xx errors)
        long errorCodeCount = httpEntries.stream()
                .map(e -> e.path("status_code").asInt(0))
                .filter(code -> code >= 400 && code < 600)
                .count();
        double statusCodeRatio = httpEntries.isEmpty() ? 0.0 : (double) errorCodeCount / httpEntries.size();

        // Method frequency skew
        Frequency methodFreq = new Frequency();
        httpEntries.forEach(e -> methodFreq.addValue(e.path("method").asText("")));
        double[] methodCounts = new double[(int) methodFreq.getUniqueCount()];
        Iterator<Comparable<?>> iterator = methodFreq.valuesIterator();
        for (int i = 0; iterator.hasNext(); i++) {
            methodCounts[i] = methodFreq.getCount(iterator.next());
        }
        DescriptiveStatistics stats = new DescriptiveStatistics(methodCounts);
        double methodSkew = stats.getSkewness();

        Map<String, Double> features = Map.of(
                FeatureConfig.RARE_HTTP_METHODS, (double) rareMethodCount,
                FeatureConfig.URI_ANOMALIES, (double) uriAnomalyCount,
                FeatureConfig.STATUS_CODE_RATIO, statusCodeRatio,
                FeatureConfig.METHOD_FREQUENCY_SKEW, methodSkew
        );
        submitFeatures(ip, windowStart, features);
    }
}