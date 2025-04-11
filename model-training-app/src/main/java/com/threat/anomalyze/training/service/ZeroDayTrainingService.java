package com.threat.anomalyze.training.service;

import com.threat.anomalyze.commons.features.FeatureAggregator;
import com.threat.anomalyze.commons.util.ZeekTimestampConverter;
import com.threat.anomalyze.training.helper.CsvExportService;
import com.threat.anomalyze.training.util.ScatterPlotUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.csv.CSVFormat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import smile.anomaly.IsolationForest;
import smile.data.DataFrame;
import smile.io.Read;
import smile.io.Write;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class ZeroDayTrainingService implements ModelTrainingService {

    @Value("${zeek.log.path}")
    private String zeekLogPath;

    @Value("${zeek.test.log.path}")
    private String zeekTestLogPath;

    @Value("${model.path}")
    private String modelPath;

    @Value("${isolationforest.ntrees}")
    private Integer numberOfTrees;

    @Value("${isolationforest.maxDepth}")
    private Integer maxTreeDepth;

    @Value("${isolationforest.subsample}")
    private Double subSamplingRate;

    @Value("${isolationforest.extensionLevel}")
    private Integer extensionLevel;

    @Autowired
    private FeatureAggregator featureAggregator;

    @Autowired
    private CsvExportService csvExportService;

    @Autowired
    private FeatureExtractionService featureExtractionService;

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
        try {
            Map<String, Map<Long, Map<String, Double>>> trainingFeatures =
                    featureExtractionService.retrieveFeatures(zeekLogPath);
            log.info("Preprocessed training data with {} feature sets.", trainingFeatures.size());
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
        String csvPath = "features.csv"; // Configure as needed
        try {
            // Export features to CSV
            Path path = Paths.get(csvPath);
            csvExportService.exportToCsv(path, featureAggregator.getFeatureStore());
            log.info("Features exported to {}", csvPath);

            // Read and process CSV file
            CSVFormat format = CSVFormat.Builder.create()
                    .setHeader()
                    .setSkipHeaderRecord(true)
                    .setDelimiter(',')
                    .get();
            DataFrame df = Read.csv(path, format);
            DataFrame modifiedDf = df.drop("ip", "timestamp");

            // Train Isolation Forest model
            IsolationForest.Options options = new IsolationForest.Options(
                    numberOfTrees, maxTreeDepth, subSamplingRate, extensionLevel);
            IsolationForest model = IsolationForest.fit(modifiedDf.toArray(), options);
            log.info("Isolation Forest model trained successfully");

            // Save the trained model
            Write.object(model, Paths.get("isolation_forest_model.ser"));
            log.info("Model saved to isolation_forest_model.ser");

            // Save the scatter plot
            ScatterPlotUtils.saveScatterPlot(modifiedDf, "zeroday_scatter_plot.png");

        } catch (IOException e) {
            log.error("Failed to export features to CSV", e);
            throw new TrainingException("Failed to export features", e);
        } catch (Exception e) {
            log.error("An error occurred during model training", e);
            throw new TrainingException("Model training failed", e);
        }
    }


    @Override
    public void evaluateModel() {
        try {
            // Step 1: Extract features from test logs
            Map<String, Map<Long, Map<String, Double>>> testFeatures = featureExtractionService.retrieveFeatures(zeekTestLogPath);
            if (testFeatures.isEmpty()) {
                log.warn("No features extracted from test logs at {}.", zeekTestLogPath);
                return;
            }
            log.info("Extracted {} feature sets from test logs.", testFeatures.size());

            // Step 2: Load the trained Isolation Forest model
            IsolationForest model = (IsolationForest) Read.object(Paths.get("isolation_forest_model.ser"));
            log.info("Loaded trained Isolation Forest model from isolation_forest_model.ser");

            // Step 3: Export test features to CSV and create a DataFrame
            String testCsvPath = "test_features.csv";
            Path path = Paths.get(testCsvPath);
            csvExportService.exportToCsv(path, testFeatures);
            CSVFormat format = CSVFormat.Builder.create()
                    .setHeader()
                    .setSkipHeaderRecord(true)
                    .setDelimiter(',')
                    .get();
            DataFrame testDf = Read.csv(path, format);

            // Step 4: Prepare feature DataFrame by dropping 'ip' and 'timestamp'
            DataFrame featuresDf = testDf.drop("ip", "timestamp");

            // Step 5: Score the test features using the model
            double[] scores = model.score(featuresDf.toArray());
            log.info("Computed anomaly scores for {} test instances.", scores.length);

            // Step 6: Associate scores with 'ip' and 'timestamp'
            List<Map<String, Object>> scoresList = new ArrayList<>();
            String[] ips = testDf.column("ip").toStringArray();
            double[] timestamps = testDf.column("timestamp").toDoubleArray();

            for (int i = 0; i < scores.length; i++) {
                Map<String, Object> scoreMap = new HashMap<>();
                scoreMap.put("ip", ips[i]);
                scoreMap.put("timestamp", ZeekTimestampConverter
                        .toHumanReadableUtc(timestamps[i]));
                scoreMap.put("anomaly_score", scores[i]);
                scoresList.add(scoreMap);
            }

            // Step 7: Export results to CSV
            String scoresCsvPath = "test_scores.csv";
            List<String> headers = List.of("ip", "timestamp", "anomaly_score");
            csvExportService.exportToCsv(Paths.get(scoresCsvPath), scoresList, headers);
            log.info("Test scores saved to {}", scoresCsvPath);
            ScatterPlotUtils.saveScatterPlot(featuresDf, "zeroday_scatter_plot_Wednesday.png");
        } catch (IOException e) {
            log.error("Failed to process test logs or export data: {}", e.getMessage(), e);
            throw new TrainingException("Error during model evaluation", e);
        } catch (Exception e) {
            log.error("Unexpected error during model evaluation: {}", e.getMessage(), e);
            throw new TrainingException("Model evaluation failed", e);
        }
    }

    public static class TrainingException extends RuntimeException {
        public TrainingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}