package com.threat.anomalyze.training.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.threat.anomalyze.commons.features.FeatureAggregator;
import com.threat.anomalyze.commons.features.IFeatureExtractor;
import com.threat.anomalyze.commons.parser.LogParser;
import com.threat.anomalyze.training.helper.CsvExportService;
import com.threat.anomalyze.training.helper.ZeekLogWindowProcessorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;

@Service
@Slf4j
public class ZeroDayTrainingService implements ModelTrainingService {

    @Value("${zeek.log.path}")
    private String zeekLogPath;

    @Value("${model.path}")
    private String modelPath;

    private final long windowSizeMs = 60_000;

    @Autowired
    private LogParser logParser;

    @Autowired
    private ZeekLogWindowProcessorService zeekLogWindowProcessorService;

    @Autowired
    private FeatureAggregator featureAggregator;

    @Autowired
    private CsvExportService csvExportService;

    @Autowired
    private List<IFeatureExtractor> featureExtractors;

    @Override
    public void startTraining() {
        try {
            preprocessData();
            trainAnomalyDetectionModel();
            evaluateModel();
        } catch (TrainingException e) {
            log.error("Training failed: {}", e.getMessage(), e);
            throw e;
        }
    }

    private void preprocessData() throws TrainingException {
        log.info("Starting data preprocessing...");
        try {
            List<String> logTypes = List.of("conn", "http", "dns", "ssl"); //notice has been skipped
            for (String logType : logTypes) {
                String logFilePath = zeekLogPath + "/" + logType + ".log";
                List<JsonNode> logs = logParser.parseLogFile(logFilePath);
                log.info("Parsed {} {} log entries.", logs.size(), logType);
                zeekLogWindowProcessorService.processLogEntries(logType, logs);
            }

            zeekLogWindowProcessorService.flushAllWindows();
            BlockingQueue<ZeekLogWindowProcessorService.WindowData> processingQueue =
                    zeekLogWindowProcessorService.getProcessingQueue();
            List<ZeekLogWindowProcessorService.WindowData> processedWindows = new ArrayList<>();
            processingQueue.drainTo(processedWindows);
            log.info("Retrieved {} processed windows.", processedWindows.size());

            if (processedWindows.isEmpty()) {
                log.warn("No processed windows available for feature extraction.");
            }

            for (ZeekLogWindowProcessorService.WindowData windowData : processedWindows) {
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
            }
            log.info("Data preprocessing completed successfully.");
        } catch (IOException e) {
            log.error("Failed to parse log file: {}", e.getMessage(), e);
            throw new TrainingException("Error parsing log file during preprocessing", e);
        } catch (Exception e) {
            log.error("Unexpected error during preprocessing: {}", e.getMessage(), e);
            throw new TrainingException("Unexpected error during data preprocessing", e);
        }
    }

    @Override
    public void trainAnomalyDetectionModel() {
        try {
            String csvPath = "features.csv"; // Configure as needed
            csvExportService.exportToCsv(Paths.get(csvPath), featureAggregator.getFeatureStore());
            log.info("Features exported to {}", csvPath);
            // Add model training logic here (e.g., using a machine learning library)
        } catch (IOException e) {
            log.error("Failed to export features to CSV", e);
            throw new TrainingException("Failed to export features", e);
        }
    }

    @Override
    public void evaluateModel() {
        // Implement model evaluation logic here
    }

    public static class TrainingException extends RuntimeException {
        public TrainingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}