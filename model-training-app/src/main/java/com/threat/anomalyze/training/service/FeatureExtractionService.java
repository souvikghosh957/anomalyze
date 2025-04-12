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
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Service to extract features from Zeek log files for anomaly detection.
 */
@Service
@Slf4j
public class FeatureExtractionService {

    private static final List<String> LOG_TYPES = List.of("conn", "http", "dns", "ssl", "notice");

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
     * @throws Exception If log parsing or feature extraction fails.
     */
    public Map<String, Map<Long, Map<String, Double>>> retrieveFeatures(String logPath) throws Exception {
        featureAggregator.clear();

        // Process logs in parallel
        processLogFilesInParallel(logPath);

        // Flush and collect
        List<ZeekLogWindowProcessorService.WindowData> processedWindows = flushAndCollectWindows(logPath);

        // Extract features
        extractFeaturesFromWindows(processedWindows);

        return featureAggregator.getFeatureStore();
    }

    private void processLogFilesInParallel(String logPath) {
        ExecutorService executor = Executors.newFixedThreadPool(LOG_TYPES.size());
        for (String logType : LOG_TYPES) {
            executor.submit(() -> processLogType(logPath, logType));
        }
        executor.shutdown();
        try {
            if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                executor.shutdownNow();
                log.warn("Log processing timed out after 60 seconds.");
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
            log.error("Interrupted during log processing.", e);
        }
    }

    private void processLogType(String logPath, String logType) {
        String logFilePath = Paths.get(logPath, logType+ "_sorted" + ".log").toString();
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
        BlockingQueue<ZeekLogWindowProcessorService.WindowData> processingQueue =
                zeekLogWindowProcessorService.getProcessingQueue();
        List<ZeekLogWindowProcessorService.WindowData> processedWindows = new ArrayList<>();
        processingQueue.drainTo(processedWindows);

        if (processedWindows.isEmpty()) {
            log.warn("No processed windows available from logs at {}.", logPath);
        }
        return processedWindows;
    }

    private void extractFeaturesFromWindows(List<ZeekLogWindowProcessorService.WindowData> processedWindows) {
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        for (ZeekLogWindowProcessorService.WindowData windowData : processedWindows) {
            executor.submit(() -> {
                String ip = windowData.ip;
                long windowStart = windowData.windowStart;
                Map<String, List<JsonNode>> logEntriesByType = windowData.logEntriesByType;
                for (IFeatureExtractor extractor : featureExtractors) {
                    try {
                        extractor.extractFeatures(ip, windowStart, logEntriesByType);
                    } catch (Exception e) {
                        log.error("Failed to extract features for IP: {} in window: {}", ip, windowStart, e);
                    }
                }
            });
        }
        executor.shutdown();
        try {
            executor.awaitTermination(60, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
            log.error("Feature extraction interrupted", e);
        }
    }
}