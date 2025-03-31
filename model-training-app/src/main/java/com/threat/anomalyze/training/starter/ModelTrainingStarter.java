package com.threat.anomalyze.training.starter;

import com.threat.anomalyze.training.service.ZeroDayTrainingService;
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
    ZeroDayTrainingService zeroDayTrainingService;


    @Override
    public void run(String... args) throws Exception {
        try {
            zeroDayTrainingService.startTraining();

        } catch (Exception e) {
            log.error("Failed to start training", e);
        } finally {
            log.info("Exiting the application...");
            SpringApplication.exit(context, () -> 0);
        }


    }
}
