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

    private static final String VERSION_FIELD = "version";
    private static final String CIPHER_FIELD = "cipher";
    private static final String JA3_FIELD = "ja3";
    private static final String ISSUER_FIELD = "issuer";
    private static final String SUBJECT_FIELD = "subject";
    private static final String ESTABLISHED_FIELD = "established";
    private static final String CURVE_FIELD = "curve";
    private static final String RESUMED_FIELD = "resumed";
    private static final String NEXT_PROTOCOL_FIELD = "next_protocol";

    // Weak ciphers from Zeek logs
    private static final Set<String> WEAK_CIPHERS = Set.of(
            "TLS_RSA_WITH_RC4_128_MD5",
            "TLS_RSA_WITH_RC4_128_SHA",
            "TLS_RSA_WITH_DES_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    );

    // Weak elliptic curves
    private static final Set<String> WEAK_CURVES = Set.of(
            "secp160r1", "secp192r1", "sect163k1"
    );

    // Outdated SSL/TLS versions
    private static final Set<String> OUTDATED_VERSIONS = Set.of(
            "SSLV2", "SSLV3", "TLSV10", "TLSV11"
    );

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

        // Outdated SSL/TLS Versions
        long outdatedSslCount = sslEntries.stream()
                .map(e -> e.path(VERSION_FIELD).asText("").toUpperCase())
                .filter(OUTDATED_VERSIONS::contains)
                .count();

        // Weak Ciphers
        long weakCipherCount = sslEntries.stream()
                .map(e -> e.path(CIPHER_FIELD).asText(""))
                .filter(cipher -> !cipher.isEmpty() && WEAK_CIPHERS.contains(cipher))
                .count();

        // Cipher Suite Entropy
        Frequency cipherFreq = new Frequency();
        sslEntries.forEach(e -> cipherFreq.addValue(e.path(CIPHER_FIELD).asText("")));
        double cipherEntropy = EntropyUtils.calculateEntropy(cipherFreq);

        // JA3 Entropy
        Frequency ja3Freq = new Frequency();
        sslEntries.forEach(e -> {
            String ja3 = e.path(JA3_FIELD).asText("");
            if (!ja3.isEmpty()) ja3Freq.addValue(ja3);
        });
        double ja3Entropy = EntropyUtils.calculateEntropy(ja3Freq);

        // Self-Signed Certificates
        long selfSignedCertCount = sslEntries.stream()
                .filter(e -> {
                    String issuer = e.path(ISSUER_FIELD).asText("");
                    String subject = e.path(SUBJECT_FIELD).asText("");
                    return !issuer.isEmpty() && issuer.equals(subject);
                })
                .count();

        // Handshake Failure Rate
        long handshakeFailureCount = sslEntries.stream()
                .filter(e -> !e.path(ESTABLISHED_FIELD).asBoolean(true))
                .count();
        double handshakeFailureRate = sslEntries.isEmpty() ? 0.0 : (double) handshakeFailureCount / sslEntries.size();

        // SSL/TLS Version Entropy
        Frequency versionFreq = new Frequency();
        sslEntries.forEach(e -> versionFreq.addValue(e.path(VERSION_FIELD).asText("")));
        double versionEntropy = EntropyUtils.calculateEntropy(versionFreq);

        // Weak Curve Count
        long weakCurveCount = sslEntries.stream()
                .map(e -> e.path(CURVE_FIELD).asText(""))
                .filter(curve -> !curve.isEmpty() && WEAK_CURVES.contains(curve))
                .count();

        // Resumption Rate
        long resumedCount = sslEntries.stream()
                .filter(e -> e.path(RESUMED_FIELD).asBoolean(false))
                .count();
        double resumptionRate = sslEntries.isEmpty() ? 0.0 : (double) resumedCount / sslEntries.size();

        // Next Protocol Entropy
        Frequency nextProtocolFreq = new Frequency();
        sslEntries.forEach(e -> nextProtocolFreq.addValue(e.path(NEXT_PROTOCOL_FIELD).asText("")));
        double nextProtocolEntropy = EntropyUtils.calculateEntropy(nextProtocolFreq);

        // Submit Features
        Map<String, Double> features = Map.of(
                FeatureConfig.OUTDATED_SSL_VERSIONS, (double) outdatedSslCount,
                FeatureConfig.WEAK_CIPHERS, (double) weakCipherCount,
                FeatureConfig.CIPHER_SUITE_ENTROPY, cipherEntropy,
                FeatureConfig.JA3_ENTROPY, ja3Entropy,
                FeatureConfig.SELF_SIGNED_CERT_COUNT, (double) selfSignedCertCount,
                FeatureConfig.HANDSHAKE_FAILURE_RATE, handshakeFailureRate,
                FeatureConfig.SSL_VERSION_ENTROPY, versionEntropy,
                FeatureConfig.WEAK_CURVE_COUNT, (double) weakCurveCount,
                FeatureConfig.RESUMPTION_RATE, resumptionRate,
                FeatureConfig.NEXT_PROTOCOL_ENTROPY, nextProtocolEntropy
        );
        submitFeatures(ip, windowStart, features);
    }
}