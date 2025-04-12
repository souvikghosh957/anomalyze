package com.threat.anomalyze.training.helper;

import com.threat.anomalyze.commons.features.FeatureConfig;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class CsvExportService {

    /**
     * Exports the nested feature map to a CSV file with rows ordered by timestamp across all IPs.
     *
     * @param path         The path to the CSV file.
     * @param featureStore The feature data in the form of Map<IP, Map<Timestamp, Map<FeatureName, Value>>>
     * @throws IOException If an I/O error occurs during file writing.
     */
    public void exportToCsv(Path path, Map<String, Map<Long, Map<String, Double>>> featureStore) throws IOException {
        log.info("Starting CSV export to {}", path);

        // Validate input
        if (featureStore == null || featureStore.isEmpty()) {
            log.warn("Feature store is null or empty; no data to export to {}", path);
            return;
        }

        // Collect all feature entries for global sorting
        List<FeatureEntry> entries = new ArrayList<>();
        for (String ip : featureStore.keySet()) {
            Map<Long, Map<String, Double>> windows = featureStore.get(ip);
            for (Map.Entry<Long, Map<String, Double>> window : windows.entrySet()) {
                entries.add(new FeatureEntry(window.getKey(), ip, window.getValue()));
            }
        }

        // Sort entries by timestamp, then by IP for consistent ordering
        entries.sort(Comparator.comparingLong(FeatureEntry::timestamp).thenComparing(FeatureEntry::ip));

        // Write to CSV using CSVPrinter
        try (CSVPrinter printer = new CSVPrinter(
                Files.newBufferedWriter(path),
                CSVFormat.DEFAULT.withHeader(FeatureConfig.CSV_HEADERS.toArray(new String[0]))
        )) {
            for (FeatureEntry entry : entries) {
                List<String> rowValues = new ArrayList<>();
                rowValues.add(String.valueOf(entry.timestamp));
                rowValues.add(entry.ip);
                // Start from index 2 to skip "timestamp" and "ip" headers
                for (String feature : FeatureConfig.CSV_HEADERS.subList(2, FeatureConfig.CSV_HEADERS.size())) {
                    Double value = entry.features.getOrDefault(feature, 0.0);
                    rowValues.add(String.format("%.4f", value));
                }
                printer.printRecord(rowValues);
            }
        } catch (IOException e) {
            log.error("Failed to export CSV to {}", path, e);
            throw e;
        }

        log.info("CSV export to {} completed successfully", path);
    }

    /**
     * Exports a list of maps to a CSV file with the specified headers.
     *
     * @param path    The path to the CSV file.
     * @param data    A list of maps, where each map represents a row with column names as keys.
     * @param headers The list of column headers to be written in the CSV.
     * @throws IOException If an I/O error occurs during file writing.
     */
    public void exportToCsv(Path path, List<Map<String, Object>> data, List<String> headers) throws IOException {
        log.info("Starting CSV export to {}", path);

        // Validate input
        if (data == null || data.isEmpty()) {
            log.warn("Data is null or empty; no data to export to {}", path);
            return;
        }
        if (headers == null || headers.isEmpty()) {
            throw new IllegalArgumentException("Headers cannot be null or empty");
        }

        // Write to CSV using CSVPrinter
        try (CSVPrinter printer = new CSVPrinter(
                Files.newBufferedWriter(path),
                CSVFormat.DEFAULT.withHeader(headers.toArray(new String[0]))
        )) {
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

        log.info("CSV export to {} completed successfully", path);
    }

    // Helper class for sorting feature data
    private static class FeatureEntry {
        final long timestamp;
        final String ip;
        final Map<String, Double> features;

        FeatureEntry(long timestamp, String ip, Map<String, Double> features) {
            this.timestamp = timestamp;
            this.ip = ip;
            this.features = features;
        }

        long timestamp() {
            return timestamp;
        }

        String ip() {
            return ip;
        }
    }
}