package com.threat.anomalyze.training;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {
        "com.threat.anomalyze.training",
        "com.threat.anomalyze.commons.features"})
public class ModelTrainingApplication {
    public static void main(String[] args) {
        SpringApplication.run(ModelTrainingApplication.class, args);
    }
}
