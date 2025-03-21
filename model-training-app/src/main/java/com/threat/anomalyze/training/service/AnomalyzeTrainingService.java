package com.threat.anomalyze.training.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AnomalyzeTrainingService {

    public void preprocessData() {
        System.out.println("Preprocessing data...");
    }

    public void trainAnomalyDetectionModel() {
        System.out.println("Training anomaly detection model...");
    }

    public void evaluateModel() {
        System.out.println("Evaluating model...");
    }


}
