package com.threat.anomalyze.training;

import com.threat.anomalyze.training.service.AnomalyzeTrainingService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class ModelTrainingStarter implements CommandLineRunner {
    @Autowired
    private ApplicationContext context;

    @Autowired
    AnomalyzeTrainingService anomalyzeTrainingService;


    @Override
    public void run(String... args) throws Exception {
        try {
            anomalyzeTrainingService.preprocessData();
            anomalyzeTrainingService.trainAnomalyDetectionModel();
            anomalyzeTrainingService.evaluateModel();

        } catch (Exception e) {
            // TODO Auto-generated catch block
        } finally {
            log.info("Exiting the application...");
            SpringApplication.exit(context, () -> 0);
        }


    }
}
