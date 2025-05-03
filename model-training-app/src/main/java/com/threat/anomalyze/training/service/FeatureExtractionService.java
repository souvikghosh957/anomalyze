package com.threat.anomalyze.training.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.threat.anomalyze.commons.features.FeatureAggregator;
import com.threat.anomalyze.commons.features.IFeatureExtractor;
import com.threat.anomalyze.commons.parser.LogParser;
import com.threat.anomalyze.training.helper.ZeekLogWindowProcessorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Service to extract features from Zeek log files for anomaly detection.
 */
@Service
@Slf4j
public class FeatureExtractionService {

    private static final List<String> LOG_TYPES = List.of("conn", "http", "dns", "ssl", "files", "notice", "auth", "ssh");

    @Autowired
    private LogParser logParser;

    @Autowired
    private ZeekLogWindowProcessorService zeekLogWindowProcessorService;

    @Autowired
    private FeatureAggregator featureAggregator;

    @Autowired
    private List<IFeatureExtractor> featureExtractors;

    /**
     * Extracts features from Zeek log files located at the specified path.
     *
     * @param logPath Directory containing Zeek log files (e.g., conn.log, http.log).
     * @return A map of features: IP → Window Start → Feature Name → Value.
     * @throws Exception If log parsing or feature extraction fails critically.
     */
    public Map<String, Map<Long, Map<String, Double>>> retrieveFeatures(String logPath) throws Exception {
        featureAggregator.clear();

        processLogFilesInParallel(logPath);
        List<ZeekLogWindowProcessorService.WindowData> processedWindows = flushAndCollectWindows(logPath);
        extractFeaturesFromWindows(processedWindows);

        return featureAggregator.getFeatureStore();
    }

    private void processLogFilesInParallel(String logPath) {
        ExecutorService executor = Executors.newFixedThreadPool(LOG_TYPES.size());
        try {
            List<CompletableFuture<Void>> futures = LOG_TYPES.stream()
                    .map(logType -> CompletableFuture.runAsync(() -> processLogType(logPath, logType), executor))
                    .toList();
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        } finally {
            executor.shutdown();
        }
    }

    private void processLogType(String logPath, String logType) {
        String logFilePath = Paths.get(logPath, logType + "_sorted.log").toString();
        if (Files.exists(Paths.get(logFilePath))) {
            try {
                List<JsonNode> logs = logParser.parseLogFile(logFilePath);
                log.info("Parsed {} {} log entries from {}.", logs.size(), logType, logFilePath);
                zeekLogWindowProcessorService.processLogEntries(logType, logs);
            } catch (Exception e) {
                log.error("Failed to process log type {}: {}", logType, e.getMessage(), e);
            }
        } else {
            log.info("Log file not found: {}. Skipping.", logFilePath);
        }
    }

    private List<ZeekLogWindowProcessorService.WindowData> flushAndCollectWindows(String logPath) {
        zeekLogWindowProcessorService.flushAllWindows();
        List<ZeekLogWindowProcessorService.WindowData> processedWindows = new ArrayList<>();
        zeekLogWindowProcessorService.getProcessingQueue().drainTo(processedWindows);

        if (processedWindows.isEmpty()) {
            log.warn("No processed windows available from logs at {}.", logPath);
        }
        return processedWindows;
    }

    private void extractFeaturesFromWindows(List<ZeekLogWindowProcessorService.WindowData> processedWindows) {
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        try {
            List<CompletableFuture<Void>> futures = processedWindows.stream()
                    .map(windowData -> CompletableFuture.runAsync(() -> {
                        String ip = windowData.ip;
                        long windowStart = windowData.windowStart;
                        Map<String, List<JsonNode>> logEntriesByType = windowData.logEntriesByType;
                        for (IFeatureExtractor extractor : featureExtractors) {
                            try {
                                extractor.extractFeatures(ip, windowStart, logEntriesByType);
                            } catch (Exception e) {
                                log.error("Failed to extract features for IP: {} in window: {}", ip, windowStart, e);
                                throw new RuntimeException(e);
                            }
                        }
                    }, executor))
                    .toList();
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        } finally {
            executor.shutdown();
        }
        log.info("Completed feature extraction for {} windows.", processedWindows.size());
    }
}