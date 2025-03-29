package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Map;

public interface IFeatureExtractor {
        void extractFeatures(String ip, long windowStart, Map<String, List<JsonNode>> logEntriesByType);
}
