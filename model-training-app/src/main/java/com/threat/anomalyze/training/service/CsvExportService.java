package com.threat.anomalyze.training.service;

import com.threat.anomalyze.commons.features.FeatureConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class CsvExportService {

    public void exportToCsv(Path path, Map<String, Map<Long, Map<String, Double>>> data)
            throws IOException {

        try (BufferedWriter writer = Files.newBufferedWriter(path)) {
            // Write header
            writer.write(String.join(",", FeatureConfig.CSV_HEADERS));
            writer.newLine();

            // Write data
            data.forEach((ip, windows) -> {
                windows.forEach((timestamp, features) -> {
                    try {
                        List<String> row = new ArrayList<>();
                        row.add(String.valueOf(timestamp));
                        row.add(ip);

                        // Add all features in header order (skip timestamp and ip)
                        for (String feature : FeatureConfig.CSV_HEADERS.subList(2, FeatureConfig.CSV_HEADERS.size())) {
                            row.add(String.format("%.4f", features.getOrDefault(feature, 0.0)));
                        }

                        writer.write(String.join(",", row));
                        writer.newLine();
                    } catch (IOException e) {
                        log.error("Failed to write row for {}@{}", ip, timestamp, e);
                    }
                });
            });
        }
    }
}
