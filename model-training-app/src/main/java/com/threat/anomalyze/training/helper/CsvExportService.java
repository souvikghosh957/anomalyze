package com.threat.anomalyze.training.helper;

import com.threat.anomalyze.commons.features.FeatureConfig;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
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

    /**
     * Exports the nested feature map to a CSV file using the predefined headers.
     *
     * @param path The path to the CSV file.
     * @param data The feature data in the form of Map<IP, Map<Timestamp, Map<FeatureName, Value>>>
     * @throws IOException If an I/O error occurs.
     */
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

    /**
     * Exports a list of maps to a CSV file with the specified headers.
     *
     * @param path    The path to the CSV file.
     * @param data    A list of maps, where each map represents a row with column names as keys.
     * @param headers The list of column headers to be written in the CSV.
     * @throws IOException If an I/O error occurs.
     */
    public void exportToCsv(Path path, List<Map<String, Object>> data, List<String> headers) throws IOException {
        try (CSVPrinter printer = new CSVPrinter(Files.newBufferedWriter(path), CSVFormat.DEFAULT.withHeader(headers.toArray(new String[0])))) {
            for (Map<String, Object> row : data) {
                List<String> values = new ArrayList<>();
                for (String header : headers) {
                    Object value = row.get(header);
                    values.add(value != null ? value.toString() : "");
                }
                printer.printRecord(values);
            }
        } catch (IOException e) {
            log.error("Failed to write CSV to {}", path, e);
            throw e;
        }
    }
}