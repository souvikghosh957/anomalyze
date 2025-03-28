package com.threat.anomalyze.training.service;

public interface ModelTrainingService {
    void startTraining();
    void trainAnomalyDetectionModel();
    void evaluateModel();
}
