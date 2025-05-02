package com.threat.anomalyze.training.service;

import com.threat.anomalyze.commons.features.FeatureAggregator;
import com.threat.anomalyze.commons.util.ZeekTimestampConverter;
import com.threat.anomalyze.training.helper.CsvExportService;
import com.threat.anomalyze.training.util.MathCalculationsUtil;
import com.threat.anomalyze.training.util.ScatterPlotUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.csv.CSVFormat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import smile.anomaly.IsolationForest;
import smile.data.DataFrame;
import smile.data.vector.LongVector;
import smile.data.vector.StringVector;
import smile.io.CSV;
import smile.io.Read;
import smile.io.Write;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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

    @Value("${anomaly.score.threshold:0.5}")
    private double anomalyScoreThreshold;

    @Value("${zscore.threshold:2.0}")
    private double zScoreThreshold;

    @Value("${max.contributing.features:5}")
    private int maxContributingFeatures;

    @Autowired
    private FeatureAggregator featureAggregator;

    @Autowired
    private CsvExportService csvExportService;

    @Autowired
    private FeatureExtractionService featureExtractionService;

    // Instance variables to store feature statistics
    private Map<String, Double> means;
    private Map<String, Double> stds;

    // Define model name in a constant
    private static final String ZERO_DAY_DETECTION_MODEL = "zeroday-detection-model.ser";

    // Define constants for CSV file paths
    private static final String TRAINING_FEATURE_CSV_PATH = "training_features.csv";
    private static final String EVALUATION_FEATURE_CSV_PATH = "evaluation_features.csv";
    private static final String EVALUATION_SCORES = "evaluation_scores.csv";

    // Define headers for anomaly CSV
    private static final List<String> ANOMALY_CSV_HEADERS = Arrays.asList(
            "ip", "timestamp", "anomaly_score", "contributing_features"
    );

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

            // Predict scores on training data to identify normal instances
            double[] scores = model.score(modifiedDf.toArray());

            // Compute means and stds for normal instances using MathUtil
            this.means = MathCalculationsUtil.computeFeatureMeans(df, scores, anomalyScoreThreshold);
            this.stds = MathCalculationsUtil.computeFeatureStds(df, scores, this.means, anomalyScoreThreshold);

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
            Path modelFile = Paths.get(ZERO_DAY_DETECTION_MODEL);
            if (!Files.exists(modelFile)) {
                throw new IllegalStateException("Model file not found at " + modelFile);
            }
            IsolationForest model = (IsolationForest) Read.object(modelFile);
            log.info("Loaded trained Isolation Forest model from {}", ZERO_DAY_DETECTION_MODEL);

            // Step 3: Export features to CSV and create a DataFrame
            Path csvPath = Paths.get(EVALUATION_FEATURE_CSV_PATH);
            csvExportService.exportToCsv(csvPath, testFeatures);
            CSVFormat format = CSVFormat.Builder.create()
                    .setHeader()
                    .setSkipHeaderRecord(true)
                    .setDelimiter(',')
                    .get();
            DataFrame testDf = new CSV(format).read(csvPath);

            // Step 4: Prepare feature DataFrame by dropping 'ip' and 'timestamp'
            DataFrame featuresDf = testDf.drop("ip", "timestamp");
            String[] featureNames = featuresDf.names();

            // Step 5: Score the test features using the model
            double[][] featureArray = featuresDf.toArray();
            double[] scores = model.score(featureArray);
            log.info("Computed anomaly scores for {} test instances.", scores.length);

            // Step 6: Use stored means and standard deviations
            Map<String, Double> means = this.means;
            Map<String, Double> stds = this.stds;
            if (means == null || stds == null) {
                throw new IllegalStateException("Feature statistics not computed. Train the model first.");
            }

            // Step 7: Filter anomalies and identify contributing features
            StringVector ipColumn = (StringVector) testDf.column("ip");
            LongVector tsColumn = (LongVector) testDf.column("timestamp");
            List<Map<String, Object>> anomalyList = new ArrayList<>();

            for (int i = 0; i < scores.length; i++) {
                if (scores[i] > anomalyScoreThreshold) {
                    Map<String, Object> anomaly = new HashMap<>();
                    anomaly.put("ip", ipColumn.getString(i));
                    anomaly.put("timestamp", ZeekTimestampConverter.toHumanReadableUtc(tsColumn.getLong(i)));
                    anomaly.put("anomaly_score", scores[i]);

                    // Collect contributing features with z-scores
                    List<Map.Entry<String, Double>> contributorEntries = new ArrayList<>();
                    for (String feature : featureNames) {
                        int colIndex = featuresDf.schema().indexOf(feature);
                        double value = featuresDf.getDouble(i, colIndex);
                        double mean = means.getOrDefault(feature, 0.0);
                        double std = stds.getOrDefault(feature, 1.0);
                        double zScore = Math.abs(value - mean) / std;
                        if (zScore > zScoreThreshold) {
                            contributorEntries.add(new AbstractMap.SimpleEntry<>(feature, zScore));
                        }
                    }

                    // Sort by z-score in descending order (highest to lowest)
                    contributorEntries.sort((e1, e2) -> Double.compare(e2.getValue(), e1.getValue()));

                    // Format the contributing features string, limited to maxContributingFeatures
                    String contributingFeatures = contributorEntries.stream()
                            .limit(maxContributingFeatures)
                            .map(e -> e.getKey() + " (z=" + String.format("%.2f", e.getValue()) + ")")
                            .collect(Collectors.joining(", "));

                    // Add to anomaly map
                    anomaly.put("contributing_features", contributingFeatures);
                    anomalyList.add(anomaly);
                }
            }

            // Step 8: Export anomalies to CSV using CsvExportService
            if (anomalyList.isEmpty()) {
                log.warn("No anomalies with scores above {} found.", anomalyScoreThreshold);
            } else {
                Path outputPath = Paths.get("anomalies_with_contributors.csv");
                csvExportService.exportToCsv(outputPath, anomalyList, ANOMALY_CSV_HEADERS);
                log.info("Anomalies saved to {}", outputPath);
            }

            // Step 9: Log summary statistics
            long anomalyCount = anomalyList.size();
            double avgScore = Arrays.stream(scores).average().orElse(0.0);
            log.info("Detected {} anomalies out of {} instances. Average score: {}",
                    anomalyCount, scores.length, avgScore);

        } catch (IOException e) {
            log.error("Failed to process test logs or export data: {}", e.getMessage(), e);
            throw new RuntimeException("Error during model evaluation", e);
        } catch (Exception e) {
            log.error("Unexpected error during model evaluation: {}", e.getMessage(), e);
            throw new RuntimeException("Model evaluation failed", e);
        }
    }

    public static class TrainingException extends RuntimeException {
        public TrainingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}