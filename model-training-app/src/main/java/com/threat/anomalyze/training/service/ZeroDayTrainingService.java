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

    // Define model name in a constant
    private static final String ZERO_DAY_DETECTION_MODEL = "zeroday-detection-model.ser";

    // Define a constant for the CSV file path
    private static final String TRAINING_FEATURE_CSV_PATH = "training_features.csv";
    private static final String EVALUATION_FEATURE_CSV_PATH = "evaluation_features.csv";
    private static final String EVALUATION_SCORES = "evaluation_scores.csv";

    @Override
    public void startTraining() {
        try {
            prepareTrainingData();
            trainAnomalyDetectionModel();
            evaluateModel();
        } catch (TrainingException e) {
            log.error("Training failed: {}", e.getMessage(), e);
            throw e;
        }
    }

    private void prepareTrainingData() throws TrainingException {
        try {
            // Extract features from the logs
            Map<String, Map<Long, Map<String, Double>>> trainingFeatures =
                    featureExtractionService.retrieveFeatures(zeekLogPath);
            log.info("Preprocessed training data with {} feature sets.", trainingFeatures.size());

            // Export features to CSV
            Path path = Paths.get(TRAINING_FEATURE_CSV_PATH);
            csvExportService.exportToCsv(path, trainingFeatures);
            log.info("Features exported to {}", TRAINING_FEATURE_CSV_PATH);
        } catch (IOException e) {
            log.error("Failed to parse log file or export CSV: {}", e.getMessage(), e);
            throw new TrainingException("Error during data preprocessing", e);
        } catch (Exception e) {
            log.error("Unexpected error during preprocessing: {}", e.getMessage(), e);
            throw new TrainingException("Unexpected error during data preprocessing", e);
        }
    }

    @Override
    public void trainAnomalyDetectionModel() {
        try {
            log.info("Reading training data from {}", TRAINING_FEATURE_CSV_PATH);
            Path path = Paths.get(TRAINING_FEATURE_CSV_PATH);
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
            log.info("Isolation Forest model for ZeroDay detection trained successfully");

            // Save the trained model
            Write.object(model, Paths.get(ZERO_DAY_DETECTION_MODEL));
            log.info("Model saved to {}", ZERO_DAY_DETECTION_MODEL);

            // Save the scatter plot
            ScatterPlotUtils.saveScatterPlot(modifiedDf, "zeroday_scatter_plot_training.png");
        } catch (IOException e) {
            log.error("Failed to read CSV or save model: {}", e.getMessage(), e);
            throw new TrainingException("Error during model training", e);
        } catch (Exception e) {
            log.error("Unexpected error during model training: {}", e.getMessage(), e);
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
            IsolationForest model = (IsolationForest) Read.object(Paths.get(ZERO_DAY_DETECTION_MODEL));
            log.info("Loaded trained Isolation Forest model from {}", ZERO_DAY_DETECTION_MODEL);

            // Step 3: Export test features to CSV and create a DataFrame
            Path path = Paths.get(EVALUATION_FEATURE_CSV_PATH);
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

            List<String> headers = List.of("ip", "timestamp", "anomaly_score");
            csvExportService.exportToCsv(Paths.get(EVALUATION_SCORES), scoresList, headers);
            log.info("Evaluation scores saved to {}", EVALUATION_SCORES);
            ScatterPlotUtils.saveScatterPlot(featuresDf, "zeroday_scatter_plot_evaluation.png");
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