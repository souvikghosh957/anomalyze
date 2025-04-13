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

    private final Set<String> knownJa3Db;

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
                .map(e -> e.path("version").asText(""))
                .filter(version -> "SSLv2".equals(version) || "SSLv3".equals(version))
                .count();

        // Weak ciphers (expanded)
        long weakCipherCount = sslEntries.stream()
                .map(e -> e.path("cipher").asText(""))
                .filter(cipher -> cipher.contains("RC4") || cipher.contains("DES") ||
                        cipher.contains("3DES") || cipher.contains("MD5"))
                .count();

        // Cipher suite entropy
        Frequency cipherFreq = new Frequency();
        sslEntries.forEach(e -> cipherFreq.addValue(e.path("cipher").asText("")));
        double cipherEntropy = EntropyUtils.calculateEntropy(cipherFreq);

        // JA3 entropy (replacing similarity)
        Frequency ja3Freq = new Frequency();
        sslEntries.forEach(e -> {
            String ja3 = generateJa3Hash(e);
            if (!ja3.isEmpty()) ja3Freq.addValue(ja3);
        });
        double ja3Entropy = EntropyUtils.calculateEntropy(ja3Freq);

        // Self-signed certificate count
        long selfSignedCertCount = sslEntries.stream()
                .filter(e -> {
                    String issuer = e.path("issuer").asText("");
                    String subject = e.path("subject").asText("");
                    return !issuer.isEmpty() && issuer.equals(subject);
                })
                .count();

        // Handshake failure rate
        long handshakeFailureCount = sslEntries.stream()
                .filter(e -> "handshake_failure".equals(e.path("conn_state").asText("")))
                .count();
        double handshakeFailureRate = sslEntries.isEmpty() ? 0.0 : (double) handshakeFailureCount / sslEntries.size();

        // SSL/TLS version entropy
        Frequency versionFreq = new Frequency();
        sslEntries.forEach(e -> versionFreq.addValue(e.path("version").asText("")));
        double versionEntropy = EntropyUtils.calculateEntropy(versionFreq);

        // Submit features
        Map<String, Double> features = Map.of(
                FeatureConfig.OUTDATED_SSL_VERSIONS, (double) outdatedSslCount,
                FeatureConfig.WEAK_CIPHERS, (double) weakCipherCount,
                FeatureConfig.CIPHER_SUITE_ENTROPY, cipherEntropy,
                FeatureConfig.JA3_ENTROPY, ja3Entropy,
                FeatureConfig.SELF_SIGNED_CERT_COUNT, (double) selfSignedCertCount,
                FeatureConfig.HANDSHAKE_FAILURE_RATE, handshakeFailureRate,
                FeatureConfig.SSL_VERSION_ENTROPY, versionEntropy
        );
        submitFeatures(ip, windowStart, features);
    }

    private String generateJa3Hash(JsonNode entry) {
        // TODO: Implement actual JA3 hashing using version, cipher, extensions, etc.
        return "dummy-ja3-hash"; // Replace with real implementation
    }
}