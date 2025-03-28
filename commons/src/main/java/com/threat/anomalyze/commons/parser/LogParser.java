package com.threat.anomalyze.commons.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Slf4j
public class LogParser {
    private final ObjectMapper mapper;

    public LogParser(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public List<JsonNode> parseLogFile(String filePath) throws Exception {
        if (filePath == null || filePath.trim().isEmpty()) {
            log.error("File path must not be null or empty: {}", filePath);
            throw new IllegalArgumentException("The filePath must not be null/empty");
        }

        Path path = Paths.get(filePath);
        List<JsonNode> entries = new ArrayList<>();

        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                processLine(line, entries);
            }
        } catch (IOException e) {
            log.error("Failed to read file: {}", filePath, e);
            throw e;
        }

        return Collections.unmodifiableList(entries);
    }


    private void processLine(String line, List<JsonNode> entries) {
        String trimmedLine = line.trim();
        if (trimmedLine.isEmpty()) {
            log.debug("Skipped empty line");
            return;
        }

        try {
            JsonNode entry = mapper.readTree(trimmedLine);
            entries.add(entry);
        } catch (JsonProcessingException e) {
            log.warn("Skipped invalid JSON line: {}", trimmedLine, e);
        }
    }

}
