package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;
import com.threat.anomalyze.commons.util.EntropyUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.Frequency;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
public class DnsFeatureExtractor extends BaseFeatureExtractor implements IFeatureExtractor {

    public DnsFeatureExtractor(FeatureAggregator aggregator) {
        super(aggregator, FeatureConfig.WINDOW_SIZE_MS);
    }

    @Override
    public void extractFeatures(String ip, long windowStart, Map<String, List<JsonNode>> logEntriesByType) {
        List<JsonNode> dnsEntries = logEntriesByType.get("dns");
        if (dnsEntries == null || dnsEntries.isEmpty()) {
            log.debug("No dns entries for IP: {} in window: {}", ip, windowStart);
            return;
        }

        // Feature: DNS query frequency
        int queryFreq = dnsEntries.size();

        // Feature: Unique queried domains
        Set<String> uniqueDomains = dnsEntries.stream()
                .map(e -> e.path("query").asText(""))
                .filter(query -> !query.isEmpty())
                .collect(Collectors.toSet());

        // Feature: Query type entropy
        Frequency qtypeFreq = new Frequency();
        dnsEntries.forEach(e -> {
            String qtype = e.path("qtype_name").asText("");
            if (!qtype.isEmpty()) {
                qtypeFreq.addValue(qtype);
            } else {
                log.warn("Missing 'qtype_name' for IP: {} in window: {}", ip, windowStart);
            }
        });
        double qtypeEntropy = EntropyUtils.calculateEntropy(qtypeFreq);

        // New Feature: NXDOMAIN ratio
        long nxdomainCount = dnsEntries.stream()
                .filter(e -> "NXDOMAIN".equals(e.path("rcode_name").asText("")))
                .count();
        double nxdomainRatio = queryFreq > 0 ? (double) nxdomainCount / queryFreq : 0.0;

        // New Feature: Query length entropy
        Frequency queryLengthFreq = new Frequency();
        dnsEntries.forEach(e -> {
            String query = e.path("query").asText("");
            if (!query.isEmpty()) {
                queryLengthFreq.addValue(query.length());
            }
        });
        double queryLengthEntropy = EntropyUtils.calculateEntropy(queryLengthFreq);

        // New Feature: Subdomain level average
        double totalSubdomainLevels = 0;
        int validDomainCount = 0;
        for (JsonNode entry : dnsEntries) {
            String query = entry.path("query").asText("");
            if (!query.isEmpty()) {
                int levels = query.split("\\.").length - 1; // e.g., sub.example.com -> 2
                totalSubdomainLevels += levels;
                validDomainCount++;
            }
        }
        double subdomainLevelAvg = validDomainCount > 0 ? totalSubdomainLevels / validDomainCount : 0.0;

        // Feature: Average query-response time (optimized)
        double queryResponseTimeAvg = calculateQueryResponseTimeAvg(dnsEntries);

        // Feature: Domain age anomaly count
        int domainAgeAnomaly = calculateDomainAgeAnomaly(dnsEntries);

        // Submit all features
        Map<String, Double> features = Map.of(
                FeatureConfig.DNS_QUERY_FREQUENCY, (double) queryFreq,
                FeatureConfig.DNS_UNIQUE_DOMAIN, (double) uniqueDomains.size(),
                FeatureConfig.DOMAIN_ENTROPY, qtypeEntropy,
                FeatureConfig.QUERY_RESPONSE_TIME_AVG, queryResponseTimeAvg,
                FeatureConfig.DOMAIN_AGE_ANOMALY, (double) domainAgeAnomaly,
                FeatureConfig.NXDOMAIN_RATIO, nxdomainRatio,
                FeatureConfig.QUERY_LENGTH_ENTROPY, queryLengthEntropy,
                FeatureConfig.SUBDOMAIN_LEVEL_AVG, subdomainLevelAvg
        );

        submitFeatures(ip, windowStart, features);
    }

    /**
     * Optimized calculation of average query-response time using a map.
     */
    private double calculateQueryResponseTimeAvg(List<JsonNode> dnsEntries) {
        Map<String, Double> queryTimestamps = new HashMap<>();
        List<Double> timeDifferences = new ArrayList<>();

        for (JsonNode entry : dnsEntries) {
            String uid = entry.path("uid").asText("");
            String transId = entry.path("trans_id").asText("");
            if (uid.isEmpty() || transId.isEmpty()) {
                log.warn("Missing 'uid' or 'trans_id' in DNS entry for timestamp: {}", entry.path("ts").asText(""));
                continue;
            }
            String key = uid + "_" + transId;
            double ts = entry.path("ts").asDouble(0.0);

            if (entry.has("answers") && !entry.get("answers").isEmpty()) {
                // This is a response
                if (queryTimestamps.containsKey(key)) {
                    double queryTs = queryTimestamps.get(key);
                    double diff = ts - queryTs;
                    if (diff > 0) {
                        timeDifferences.add(diff);
                    }
                    queryTimestamps.remove(key); // Remove after matching
                }
            } else {
                // This is a query
                queryTimestamps.put(key, ts);
            }
        }

        return timeDifferences.isEmpty() ? 0.0 :
                timeDifferences.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
    }

    /**
     * Counts the number of queried domains with an age less than 30 days.
     */
    private int calculateDomainAgeAnomaly(List<JsonNode> dnsEntries) {
        int anomalies = 0;
        for (JsonNode entry : dnsEntries) {
            String domain = entry.path("query").asText("");
            if (!domain.isEmpty()) {
                LocalDateTime creationDate = getWhoisCreationDate(domain);
                long ageDays = ChronoUnit.DAYS.between(creationDate, LocalDateTime.now());
                if (ageDays < 30) {
                    anomalies++;
                }
            }
        }
        return anomalies;
    }

    /**
     * Placeholder for WHOIS lookup to get a domain's creation date.
     * TODO: Replace with actual WHOIS service or cached database.
     */
    private LocalDateTime getWhoisCreationDate(String domain) {
        // Dummy implementation (assumes domain is 1 year old)
        return LocalDateTime.now().minusYears(1);
    }
}