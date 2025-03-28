package com.threat.anomalyze.commons.features;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class FeatureAggregator {
    // IP -> WindowStartTimestamp -> FeatureName -> Value
    private final Map<String, Map<Long, Map<String, Double>>> featureStore = new ConcurrentHashMap<>();

    public void addFeatures(String ip, long windowStart, Map<String, Double> features) {
        featureStore.compute(ip, (key, ipMap) -> {
            if (ipMap == null) {
                ipMap = new ConcurrentHashMap<>();
            }
            ipMap.compute(windowStart, (ts, featureMap) -> {
                if (featureMap == null) {
                    featureMap = new ConcurrentHashMap<>();
                }
                featureMap.putAll(features);
                return featureMap;
            });
            return ipMap;
        });
    }

    public Map<String, Map<Long, Map<String, Double>>> getFeatureStore() {
        return Collections.unmodifiableMap(featureStore);
    }
}
