package com.threat.anomalyze.training.service;

import com.threat.anomalyze.commons.CommonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import smile.anomaly.IsolationForest;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

@Service
@Slf4j
public class AnomalyzeTrainingService {

    private static final String MODEL_PATH = "C:\\Users\\souvi\\anomalyze\\anomalyze\\model-training-app\\isolation_forest_model.ser";

    public void preprocessData() {
        log.info("Preprocessing data...");

        // Retrieve data from Zeek logs and convert to CSV (for now, just a placeholder)
        log.info("Retrieving logs, cleaning, and converting to CSV...");

        // Placeholder: Load actual data from Zeek/Sysmon logs later.
    }

    public void trainAnomalyDetectionModel() {
        log.info("Training Isolation Forest anomaly detection model...");

        // Sample synthetic training data (Replace with actual preprocessed Zeek/Sysmon data)
        double[][] data = {
                {1.0, 2.0}, {1.5, 2.5}, {1.2, 2.2}, {5.0, 6.0}, {8.0, 9.0}
        };

        // Isolation Forest Configuration
        IsolationForest.Options options = new IsolationForest.Options(
                200,    // Number of trees
                256,    // Sub-sampling size
                0.1,    // Contamination level (expected % of anomalies)
                1       // Random seed for reproducibility
        );

        // Train the Isolation Forest model
        IsolationForest isolationForestModel = IsolationForest.fit(data, options);

        log.info("Model training completed successfully.");

        // Save the trained model
        saveModel(isolationForestModel);
    }

    private void saveModel(IsolationForest model) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(MODEL_PATH))) {
            oos.writeObject(model);
            log.info("Model saved successfully at: {}", MODEL_PATH);
        } catch (IOException e) {
            log.error("Error saving model: {}", e.getMessage());
        }
    }

    public void evaluateModel() {
        log.info("Evaluating Isolation Forest model...");

        // Sample test data (Replace with real test set)
        double[][] testData = {
                {1.1, 2.1}, {5.1, 6.2}, {9.0, 10.5}, {0.5, 1.2}
        };

        // Load the trained model
        IsolationForest model = loadModel();
        if (model == null) {
            log.error("Model not found. Please train the model first.");
            return;
        }

        // Predict anomalies
        for (double[] instance : testData) {
            double score = model.score(instance);
            log.info("Data: {} | Anomaly Score: {}", Arrays.toString(instance), score);
        }
    }

    private IsolationForest loadModel() {
        try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(Paths.get(MODEL_PATH)))) {
            return (IsolationForest) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            log.error("Error loading model: {}", e.getMessage());
            return null;
        }
    }
}
