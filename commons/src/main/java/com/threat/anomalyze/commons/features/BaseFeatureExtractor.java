package com.threat.anomalyze.commons.features;

import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Base class for feature extractors, providing common functionality to submit features to a FeatureAggregator
 * with time window alignment.
 */
public abstract class BaseFeatureExtractor {
    protected final FeatureAggregator aggregator;
    protected final long windowSizeMs;

    /**
     * Constructs a BaseFeatureExtractor with the specified aggregator and window size.
     *
     * @param aggregator   the FeatureAggregator to submit features to
     * @param windowSizeMs the size of the time window in milliseconds
     */
    protected BaseFeatureExtractor(FeatureAggregator aggregator, long windowSizeMs) {
        this.aggregator = aggregator;
        this.windowSizeMs = windowSizeMs;
    }

    /**
     * Submits features for a specific IP and timestamp to the aggregator, aligned to the appropriate time window.
     *
     * @param ip        the source IP address
     * @param timestamp the timestamp in milliseconds
     * @param features  a map of feature names to their double values
     * @throws IllegalArgumentException if timestamp is negative or features map is null or empty
     */
    protected void submitFeatures(String ip, long timestamp, Map<String, Double> features) {
        if (timestamp < 0) {
            throw new IllegalArgumentException("Timestamp cannot be negative");
        }
        if (features == null || features.isEmpty()) {
            throw new IllegalArgumentException("Features map cannot be null or empty");
        }
        long windowStart = timestamp - (timestamp % windowSizeMs);
        aggregator.addFeatures(ip, windowStart, features);
    }
}