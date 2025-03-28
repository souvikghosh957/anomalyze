package com.threat.anomalyze.commons.features;

import java.util.Map;

public class BaseFeatureExtractor {
    protected final FeatureAggregator aggregator;

    protected BaseFeatureExtractor(FeatureAggregator aggregator) {
        this.aggregator = aggregator;
    }

    protected void submitFeatures(String ip, long timestamp, Map<String, Double> features) {
        long windowStart = timestamp - (timestamp % FeatureConfig.WINDOW_SIZE_MS);
        aggregator.addFeatures(ip, windowStart, features);
    }
}
