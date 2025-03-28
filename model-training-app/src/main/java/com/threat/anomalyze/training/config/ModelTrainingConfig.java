package com.threat.anomalyze.training.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.threat.anomalyze.commons.parser.LogParser;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ModelTrainingConfig {

    @Bean
    public LogParser logParser(ObjectMapper springObjectMapper) {
        return new LogParser(springObjectMapper);
    }

}
