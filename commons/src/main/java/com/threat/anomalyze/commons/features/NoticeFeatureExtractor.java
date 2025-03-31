package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

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

        // Notice anomalies: count all notice entries
        long anomalyCount = noticeEntries.size();

        Map<String, Double> features = Map.of(
                FeatureConfig.NOTICE_ANOMALIES, (double) anomalyCount
        );
        submitFeatures(ip, windowStart, features);
    }
}