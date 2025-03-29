package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;
import com.threat.anomalyze.commons.util.EntropyUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.Frequency;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@Slf4j
public class SslFeatureExtractor extends BaseFeatureExtractor implements IFeatureExtractor {

    private final Set<String> knownJa3Db; // Injected known JA3 hashes

    public SslFeatureExtractor(FeatureAggregator aggregator, Set<String> knownJa3Db) {
        super(aggregator, FeatureConfig.WINDOW_SIZE_MS);
        this.knownJa3Db = knownJa3Db;
    }

    @Override
    public void extractFeatures(String ip, long windowStart, Map<String, List<JsonNode>> logEntriesByType) {
        List<JsonNode> sslEntries = logEntriesByType.get("ssl");
        if (sslEntries == null || sslEntries.isEmpty()) {
            log.debug("No ssl entries for IP: {} in window: {}", ip, windowStart);
            return;
        }

        // Outdated SSL versions
        long outdatedSslCount = sslEntries.stream()
                .map(e -> e.get("version").asText(""))
                .filter(version -> "SSLv2".equals(version) || "SSLv3".equals(version))
                .count();

        // Weak ciphers
        long weakCipherCount = sslEntries.stream()
                .map(e -> e.get("cipher").asText(""))
                .filter(cipher -> cipher.contains("RC4") || cipher.contains("DES"))
                .count();

        // Cipher suite entropy
        Frequency cipherFreq = new Frequency();
        sslEntries.forEach(e -> cipherFreq.addValue(e.get("cipher").asText("")));
        double cipherEntropy = EntropyUtils.calculateEntropy(cipherFreq);

        // JA3 similarity score
        int ja3Matches = 0;
        for (JsonNode entry : sslEntries) {
            String ja3 = generateJa3Hash(entry);
            if (knownJa3Db.contains(ja3)) ja3Matches++;
        }
        double ja3Similarity = sslEntries.isEmpty() ? 0.0 : (double) ja3Matches / sslEntries.size();

        Map<String, Double> features = Map.of(
                FeatureConfig.OUTDATED_SSL_VERSIONS, (double) outdatedSslCount,
                FeatureConfig.WEAK_CIPHERS, (double) weakCipherCount,
                FeatureConfig.CIPHER_SUITE_ENTROPY, cipherEntropy,
                FeatureConfig.JA3_SIMILARITY_SCORE, ja3Similarity
        );
        submitFeatures(ip, windowStart, features);
    }

    private String generateJa3Hash(JsonNode entry) {
        // Placeholder: Implement JA3 hashing logic
        return "dummy-ja3-hash";
    }
}