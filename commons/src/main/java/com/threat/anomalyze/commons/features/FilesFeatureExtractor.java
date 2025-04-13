package com.threat.anomalyze.commons.features;

import com.fasterxml.jackson.databind.JsonNode;
import com.threat.anomalyze.commons.util.EntropyUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.Frequency;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
public class FilesFeatureExtractor extends BaseFeatureExtractor implements IFeatureExtractor {
    private static final Set<String> EXECUTABLE_TYPES = Set.of("exe", "dll", "bat", "jar", "sh", "vbs", "ps1", "cmd");
    private static final Set<String> SUSPICIOUS_TYPES = Set.of("zip", "rar", "js", "vbs", "ps1", "pdf", "doc", "docx");

    public FilesFeatureExtractor(FeatureAggregator aggregator) {
        super(aggregator, FeatureConfig.WINDOW_SIZE_MS);
    }

    @Override
    public void extractFeatures(String ip, long windowStart, Map<String, List<JsonNode>> logEntriesByType) {
        List<JsonNode> fileEntries = logEntriesByType.get("files");
        if (fileEntries == null || fileEntries.isEmpty()) {
            log.debug("No file entries for IP: {} in window: {}", ip, windowStart);
            return;
        }

        // File type entropy
        Frequency typeFreq = new Frequency();
        fileEntries.forEach(e -> {
            String fileType = e.path("mime_type").asText("");
            if (!fileType.isEmpty()) typeFreq.addValue(fileType);
        });
        double typeEntropy = EntropyUtils.calculateEntropy(typeFreq);

        // Average file size and variance
        DescriptiveStatistics sizeStats = new DescriptiveStatistics();
        fileEntries.forEach(e -> {
            double size = e.path("seen_bytes").asDouble(-1.0);
            if (size >= 0) sizeStats.addValue(size);
        });
        double avgFileSize = sizeStats.getN() > 0 ? sizeStats.getMean() : 0.0;
        double sizeVariance = sizeStats.getN() > 0 ? sizeStats.getVariance() : 0.0;

        // Executable file ratio
        long exeCount = fileEntries.stream()
                .map(e -> e.path("mime_type").asText("").toLowerCase())
                .filter(type -> EXECUTABLE_TYPES.stream().anyMatch(type::contains) ||
                        type.contains("octet-stream")) // Catch generic executables
                .count();
        double exeRatio = fileEntries.isEmpty() ? 0.0 : (double) exeCount / fileEntries.size();

        // Suspicious file type ratio
        long suspiciousCount = fileEntries.stream()
                .map(e -> e.path("mime_type").asText("").toLowerCase())
                .filter(type -> SUSPICIOUS_TYPES.stream().anyMatch(type::contains))
                .count();
        double suspiciousRatio = fileEntries.isEmpty() ? 0.0 : (double) suspiciousCount / fileEntries.size();

        // Unique file hash count
        Set<String> uniqueHashes = fileEntries.stream()
                .map(e -> e.path("md5").asText(""))
                .filter(hash -> {
                    if (hash.isEmpty()) {
                        log.warn("Missing md5 hash for IP: {} in window: {}", ip, windowStart);
                        return false;
                    }
                    return true;
                })
                .collect(Collectors.toSet());
        long uniqueHashCount = uniqueHashes.size();

        // File transfer rate
        double windowDurationSeconds = (double) FeatureConfig.WINDOW_SIZE_MS / 1000.0;
        double fileRate = fileEntries.size() / windowDurationSeconds;

        // Protocol entropy
        Frequency protocolFreq = new Frequency();
        fileEntries.forEach(e -> {
            String protocol = e.path("source").asText("");
            if (!protocol.isEmpty()) protocolFreq.addValue(protocol);
        });
        double protocolEntropy = EntropyUtils.calculateEntropy(protocolFreq);

        // Upload ratio
        long uploadCount = fileEntries.stream()
                .filter(e -> e.path("is_orig").asBoolean(false))
                .count();
        double uploadRatio = fileEntries.isEmpty() ? 0.0 : (double) uploadCount / fileEntries.size();

        // Temporal clustering
        DescriptiveStatistics tsStats = new DescriptiveStatistics();
        fileEntries.forEach(e -> {
            double ts = e.path("ts").asDouble(-1.0);
            if (ts >= 0) tsStats.addValue(ts);
        });
        double tsVariance = tsStats.getN() > 0 ? tsStats.getVariance() : 0.0;

        // Submit features
        Map<String, Double> features = Map.of(
                FeatureConfig.FILE_TYPE_ENTROPY, typeEntropy,
                FeatureConfig.AVG_FILE_SIZE, avgFileSize,
                FeatureConfig.FILE_SIZE_VARIANCE, sizeVariance,
                FeatureConfig.EXE_RATIO, exeRatio,
                FeatureConfig.SUSPICIOUS_TYPE_RATIO, suspiciousRatio,
                FeatureConfig.UNIQUE_HASH_COUNT, (double) uniqueHashCount,
                FeatureConfig.FILE_RATE, fileRate,
                FeatureConfig.PROTOCOL_ENTROPY, protocolEntropy,
                FeatureConfig.FILE_UPLOAD_RATIO, uploadRatio,
                FeatureConfig.FILE_TS_VARIANCE, tsVariance
        );
        submitFeatures(ip, windowStart, features);
    }
}