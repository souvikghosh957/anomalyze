package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;
import com.threat.anomalyze.commons.util.EntropyUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.Frequency;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
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

        // Existing Feature: DNS query frequency
        int queryFreq = dnsEntries.size();

        // Existing Feature: Unique queried domains
        Set<String> uniqueDomains = dnsEntries.stream()
                .map(e -> e.get("query").asText(""))
                .collect(Collectors.toSet());

        // Existing Feature: Query type entropy
        Frequency qtypeFreq = new Frequency();
        dnsEntries.forEach(e -> qtypeFreq.addValue(e.get("qtype_name").asText("")));
        double qtypeEntropy = EntropyUtils.calculateEntropy(qtypeFreq);

        // New Feature: Average query-response time
        double queryResponseTimeAvg = calculateQueryResponseTimeAvg(dnsEntries);

        // New Feature: Domain age anomaly count
        int domainAgeAnomaly = calculateDomainAgeAnomaly(dnsEntries);

        // Submit all features
        Map<String, Double> features = Map.of(
                FeatureConfig.DNS_QUERY_FREQUENCY, (double) queryFreq,
                FeatureConfig.DNS_UNIQUE_DOMAIN, (double) uniqueDomains.size(),
                FeatureConfig.DOMAIN_ENTROPY, qtypeEntropy,
                FeatureConfig.QUERY_RESPONSE_TIME_AVG, queryResponseTimeAvg,
                FeatureConfig.DOMAIN_AGE_ANOMALY, (double) domainAgeAnomaly
        );

        submitFeatures(ip, windowStart, features);
    }

    /**
     * Calculates the average time between DNS queries and their responses.
     */
    private double calculateQueryResponseTimeAvg(List<JsonNode> dnsEntries) {
        List<Double> timeDiffs = new ArrayList<>();
        Map<String, List<JsonNode>> groupedById = dnsEntries.stream()
                .collect(Collectors.groupingBy(e -> e.get("trans_id").asText()));
        for (List<JsonNode> group : groupedById.values()) {
            if (group.size() == 2) { // Assuming query and response pair
                JsonNode query = group.get(0).get("QR").asText().equals("Q") ? group.get(0) : group.get(1);
                JsonNode resp = group.get(0).get("QR").asText().equals("R") ? group.get(0) : group.get(1);
                double queryTime = query.get("ts").asDouble();
                double respTime = resp.get("ts").asDouble();
                if (respTime > queryTime) {
                    timeDiffs.add(respTime - queryTime);
                }
            }
        }
        return timeDiffs.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
    }

    /**
     * Counts the number of queried domains with an age less than 30 days.
     */
    private int calculateDomainAgeAnomaly(List<JsonNode> dnsEntries) {
        int anomalies = 0;
        for (JsonNode entry : dnsEntries) {
            String domain = entry.get("query").asText();
            LocalDateTime creationDate = getWhoisCreationDate(domain);
            long ageDays = ChronoUnit.DAYS.between(creationDate, LocalDateTime.now());
            if (ageDays < 30) {
                anomalies++;
            }
        }
        return anomalies;
    }

    /**
     * Placeholder for WHOIS lookup to get a domain's creation date.
     * In practice, integrate with a WHOIS service or cached database.
     */
    private LocalDateTime getWhoisCreationDate(String domain) {
        // TODO: Replace with actual WHOIS lookup implementation
        return LocalDateTime.now().minusYears(1); // Dummy value (1 year old)
    }
}