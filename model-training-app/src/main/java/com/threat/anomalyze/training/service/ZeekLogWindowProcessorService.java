package com.threat.anomalyze.training.service;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.annotation.PreDestroy;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;


@Service
@Slf4j
public class ZeekLogWindowProcessorService {
    private final static long WINDOW_SIZE_MS = TimeUnit.MINUTES.toMillis(1);
    private final ConcurrentMap<String, Deque<WindowBucket>> connectionWindows = new ConcurrentHashMap<>();

    @Getter
    private final BlockingQueue<Map<String, List<JsonNode>>> processingQueue = new LinkedBlockingQueue<>();

    private static class WindowBucket {
        final long windowStart;
        final long windowSize;
        final List<JsonNode> entries = new CopyOnWriteArrayList<>();

        WindowBucket(long timestamp, long windowSize) {
            this.windowSize = windowSize;
            this.windowStart = timestamp - (timestamp % windowSize);
        }

        boolean isInWindow(long timestamp) {
            return timestamp >= windowStart && timestamp < windowStart + windowSize;
        }
    }

    public void processLogEntries(List<JsonNode> jsonNodes) {
        log.info("Processing batch of {} log entries", jsonNodes.size());
        jsonNodes.forEach(this::processSingleEntry);
    }

    private void processSingleEntry(JsonNode entry) {
        try {
            String sourceIp = entry.get("id.orig_h").asText();
            long entryTime = (long) (entry.get("ts").asDouble() * 1000);
            log.debug("Processing entry from {} at {}", sourceIp, entryTime);

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

                current.entries.add(entry);
                log.debug("Added entry to window starting at {} for IP: {}",
                        current.windowStart, ip);
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
                        && !bucket.entries.isEmpty();
                if (shouldRemove) {
                    log.warn("Removing stale window for IP: {} (start: {}, entries: {})",
                            ip, bucket.windowStart, bucket.entries.size());
                    removedCount[0]++;
                }
                return shouldRemove;
            });
            log.debug("IP {}: Removed {} stale buckets (from {} to {})",
                    ip, initialSize - buckets.size(), initialSize, buckets.size());
        });

        log.info("Completed stale window cleanup. Removed {} total buckets", removedCount[0]);
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
        Map<String, List<JsonNode>> windowData = new HashMap<>();
        List<JsonNode> entries = Collections.unmodifiableList(bucket.entries);
        windowData.put(ip, entries);

        if (processingQueue.offer(windowData)) {
            log.info("Submitted window for IP: {} with {} entries (start: {})",
                    ip, entries.size(), bucket.windowStart);
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