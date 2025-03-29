package com.threat.anomalyze.training.helper;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.annotation.PreDestroy;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class ZeekLogWindowProcessorService {
    private static final long WINDOW_SIZE_MS = TimeUnit.MINUTES.toMillis(1);
    private final ConcurrentMap<String, Deque<WindowBucket>> connectionWindows = new ConcurrentHashMap<>();

    @Getter
    private final BlockingQueue<WindowData> processingQueue = new LinkedBlockingQueue<>();

    public static class WindowData {
        public final String ip;
        public final long windowStart;
        public final Map<String, List<JsonNode>> logEntriesByType;

        public WindowData(String ip, long windowStart, Map<String, List<JsonNode>> logEntriesByType) {
            this.ip = ip;
            this.windowStart = windowStart;
            this.logEntriesByType = logEntriesByType;
        }
    }

    private static class WindowBucket {
        final long windowStart;
        final long windowSize;
        final Map<String, List<JsonNode>> logEntriesByType = new ConcurrentHashMap<>();

        WindowBucket(long timestamp, long windowSize) {
            this.windowSize = windowSize;
            this.windowStart = timestamp - (timestamp % windowSize);
        }

        boolean isInWindow(long timestamp) {
            return timestamp >= windowStart && timestamp < windowStart + windowSize;
        }
    }

    public void processLogEntries(String logType, List<JsonNode> jsonNodes) {
        log.info("Processing batch of {} log entries for log type {}", jsonNodes.size(), logType);
        jsonNodes.forEach(entry -> processSingleEntry(logType, entry));
    }

    private void processSingleEntry(String logType, JsonNode entry) {
        try {
            String sourceIp = entry.get("id.orig_h").asText();
            long entryTime = (long) (entry.get("ts").asDouble() * 1000);
            log.debug("Processing entry from {} at {} for log type {}", sourceIp, entryTime, logType);

            connectionWindows.compute(sourceIp, (ip, buckets) -> {
                if (buckets == null) {
                    log.info("Creating first window bucket for IP: {}", ip);
                    Deque<WindowBucket> newBuckets = new ConcurrentLinkedDeque<>();
                    newBuckets.add(createNewBucket(entryTime));
                    return newBuckets;
                }

                WindowBucket current = buckets.getLast();
                if (!current.isInWindow(entryTime)) {
                    log.info("Creating new window for IP: {} (current time: {} window start: {})",
                            ip, entryTime, current.windowStart);
                    submitWindow(ip, current);
                    current = createNewBucket(entryTime);
                    buckets.add(current);
                }

                current.logEntriesByType.computeIfAbsent(logType, k -> new CopyOnWriteArrayList<>()).add(entry);
                log.debug("Added entry to window starting at {} for IP: {} and log type: {}",
                        current.windowStart, ip, logType);
                return buckets;
            });
        } catch (Exception e) {
            log.error("Failed to process log entry: {}", entry, e);
            throw new LogProcessingException("Failed to process log entry", e);
        }
    }

    @Scheduled(fixedRate = 30_000)
    public void flushStaleWindows() {
        log.info("Starting stale window cleanup");
        long cutoff = System.currentTimeMillis() - WINDOW_SIZE_MS;
        int[] removedCount = {0};

        connectionWindows.forEach((ip, buckets) -> {
            int initialSize = buckets.size();
            buckets.removeIf(bucket -> {
                boolean shouldRemove = bucket.windowStart + bucket.windowSize < cutoff
                        && !bucket.logEntriesByType.isEmpty();
                if (shouldRemove) {
                    log.warn("Removing stale window for IP: {} (start: {}, log types: {})",
                            ip, bucket.windowStart, bucket.logEntriesByType.keySet());
                    submitWindow(ip, bucket);
                    removedCount[0]++;
                }
                return shouldRemove;
            });
            log.debug("IP {}: Removed {} stale buckets (from {} to {})",
                    ip, initialSize - buckets.size(), initialSize, buckets.size());
        });

        log.info("Completed stale window cleanup. Removed {} total buckets", removedCount[0]);
    }

    public void flushAllWindows() {
        log.info("Flushing all current windows");
        connectionWindows.forEach((ip, buckets) -> {
            buckets.forEach(bucket -> submitWindow(ip, bucket));
            buckets.clear();
        });
        log.info("All windows flushed. Queue size: {}", processingQueue.size());
    }

    @PreDestroy
    public void shutdown() {
        log.info("Shutting down window processor. Cleaning up resources.");
        processingQueue.clear();
        connectionWindows.clear();
        log.info("Shutdown complete. Queue size: {}, IP windows: {}",
                processingQueue.size(), connectionWindows.size());
    }

    private WindowBucket createNewBucket(long timestamp) {
        WindowBucket bucket = new WindowBucket(timestamp, WINDOW_SIZE_MS);
        log.debug("Created new window bucket starting at {}", bucket.windowStart);
        return bucket;
    }

    private void submitWindow(String ip, WindowBucket bucket) {
        Map<String, List<JsonNode>> logEntriesCopy = new HashMap<>();
        bucket.logEntriesByType.forEach((logType, entries) -> {
            logEntriesCopy.put(logType, List.copyOf(entries));
        });
        WindowData windowData = new WindowData(ip, bucket.windowStart, logEntriesCopy);
        if (processingQueue.offer(windowData)) {
            log.info("Submitted window for IP: {} with log types: {} (start: {})",
                    ip, logEntriesCopy.keySet(), bucket.windowStart);
        } else {
            log.error("Failed to submit window for IP: {} - processing queue full!", ip);
        }
    }

    public static class LogProcessingException extends RuntimeException {
        public LogProcessingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}