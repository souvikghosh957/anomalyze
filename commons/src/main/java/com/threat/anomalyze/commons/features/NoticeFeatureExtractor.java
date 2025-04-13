package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.Frequency;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.springframework.stereotype.Service;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class NoticeFeatureExtractor extends BaseFeatureExtractor implements IFeatureExtractor {

    public NoticeFeatureExtractor(FeatureAggregator aggregator) {
        super(aggregator, FeatureConfig.WINDOW_SIZE_MS);
    }

    @Override
    public void extractFeatures(String ip, long windowStart, Map<String, List<JsonNode>> logEntriesByType) {
        List<JsonNode> noticeEntries = logEntriesByType.get("notice");
        if (noticeEntries == null || noticeEntries.isEmpty()) {
            log.debug("No notice entries for IP: {} in window: {}", ip, windowStart);
            return;
        }

        // 1. Total notice count
        long noticeCount = noticeEntries.size();

        // 2. Notice type entropy
        Frequency typeFreq = new Frequency();
        noticeEntries.forEach(e -> {
            String type = e.path("notice_type").asText("");
            if (!type.isEmpty()) typeFreq.addValue(type);
        });
        double typeEntropy = calculateEntropy(typeFreq);

        // 3. Severity distribution (low=1, medium=2, high=3)
        DescriptiveStatistics severityStats = new DescriptiveStatistics();
        for (JsonNode entry : noticeEntries) {
            String severityStr = entry.path("severity").asText("").toLowerCase();
            double severity = mapSeverityToValue(severityStr);
            if (severity > 0) severityStats.addValue(severity);
        }
        double averageSeverity = severityStats.getN() > 0 ? severityStats.getMean() : 0.0;

        // 4. Notice rate (notices per second)
        double windowDurationSeconds = (double) FeatureConfig.WINDOW_SIZE_MS / 1000.0;
        double noticeRate = noticeCount / windowDurationSeconds;

        // 5. Temporal clustering (variance of timestamps)
        DescriptiveStatistics timestampStats = new DescriptiveStatistics();
        for (JsonNode entry : noticeEntries) {
            double ts = entry.path("ts").asDouble(0.0);
            if (ts > 0) timestampStats.addValue(ts);
        }
        double timestampVariance = timestampStats.getN() > 0 ? timestampStats.getVariance() : 0.0;

        // Submit features
        Map<String, Double> features = Map.of(
                FeatureConfig.NOTICE_COUNT, (double) noticeCount,
                FeatureConfig.NOTICE_TYPE_ENTROPY, typeEntropy,
                FeatureConfig.AVERAGE_SEVERITY, averageSeverity,
                FeatureConfig.NOTICE_RATE, noticeRate,
                FeatureConfig.NOTICE_TIMESTAMP_VARIANCE, timestampVariance
        );
        submitFeatures(ip, windowStart, features);
    }

    // Calculate entropy from frequency distribution
    private double calculateEntropy(Frequency freq) {
        if (freq.getUniqueCount() == 0) return 0.0;
        double total = freq.getSumFreq();
        double entropy = 0.0;
        for (Iterator<Comparable<?>> it = freq.valuesIterator(); it.hasNext(); ) {
            long count = freq.getCount(it.next());
            double p = count / total;
            entropy -= p * Math.log(p) / Math.log(2); // Base-2 logarithm
        }
        return entropy;
    }

    // Map severity strings to numerical values
    private double mapSeverityToValue(String severity) {
        switch (severity) {
            case "low":
                return 1.0;
            case "medium":
                return 2.0;
            case "high":
                return 3.0;
            default:
                return 0.0; // Missing or unknown severity
        }
    }
}