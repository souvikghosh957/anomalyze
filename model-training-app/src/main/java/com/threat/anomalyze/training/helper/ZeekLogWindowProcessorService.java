package com.threat.anomalyze.training.helper;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.annotation.PreDestroy;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Service to process Zeek log entries by grouping them into time-based windows per source IP.
 * Each window (bucket) contains log entries for a specific time period, and stale windows are
 * periodically flushed to a processing queue.
 */
@Service
@Slf4j
public class ZeekLogWindowProcessorService {

    // Configurable window size (default: 1 minute)
    private final long windowSizeMs;

    // Map of source IP to a sorted list of time window buckets
    private final ConcurrentMap<String, List<WindowBucket>> connectionWindows = new ConcurrentHashMap<>();

    @Getter
    private final BlockingQueue<WindowData> processingQueue = new LinkedBlockingQueue<>();

    // Flag to prevent processing after shutdown
    private volatile boolean isShuttingDown = false;

    /**
     * Data structure to hold a completed window's data for downstream processing.
     */
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

    /**
     * Represents a time window bucket containing log entries for various log types.
     */
    private static class WindowBucket {
        final long windowStart; // Start time of the window (aligned to windowSizeMs)
        final long windowSize;  // Duration of the window in milliseconds
        final Map<String, List<JsonNode>> logEntriesByType = new ConcurrentHashMap<>();

        WindowBucket(long timestamp, long windowSize) {
            this.windowSize = windowSize;
            // Align timestamp to the start of the window
            this.windowStart = timestamp - (timestamp % windowSize);
        }

        // Check if a timestamp belongs to this window
        boolean isInWindow(long timestamp) {
            return timestamp >= windowStart && timestamp < windowStart + windowSize;
        }
    }

    // Constructor to inject configurable window size
    public ZeekLogWindowProcessorService(
            @Value("${zeek.window.size.minutes:1}") long windowSizeMinutes) {
        this.windowSizeMs = TimeUnit.MINUTES.toMillis(windowSizeMinutes);
        log.info("Initialized with window size: {} ms", windowSizeMs);
    }

    /**
     * Processes a batch of log entries for a given log type by delegating to processSingleEntry.
     *
     * @param logType   The type of log (e.g., "conn", "dns")
     * @param jsonNodes List of log entries in JSON format
     */
    public void processLogEntries(String logType, List<JsonNode> jsonNodes) {
        if (isShuttingDown) {
            log.warn("Ignoring batch of {} entries for log type {}: service is shutting down",
                    jsonNodes.size(), logType);
            return;
        }
        log.info("Processing batch of {} log entries for log type {}", jsonNodes.size(), logType);
        jsonNodes.forEach(entry -> processSingleEntry(logType, entry));
    }

    /**
     * Processes a single log entry, placing it into the appropriate time window bucket for its source IP.
     *
     * @param logType The type of log
     * @param entry   The log entry as a JSON node
     */
    private void processSingleEntry(String logType, JsonNode entry) {
        if (isShuttingDown) {
            log.debug("Skipping entry processing: service is shutting down");
            return;
        }
        try {
            String sourceIp = entry.get("id.orig_h").asText();
            long entryTime = (long) (entry.get("ts").asDouble() * 1000);
            log.debug("Processing entry from IP {} at timestamp {} for log type {}",
                    sourceIp, entryTime, logType);

            // Atomically update or create the bucket list for this IP
            connectionWindows.compute(sourceIp, (ip, buckets) -> {
                if (buckets == null) {
                    log.info("Initializing bucket list for IP: {}", ip);
                    buckets = new ArrayList<>();
                    WindowBucket newBucket = createNewBucket(entryTime);
                    buckets.add(newBucket);
                    addEntryToBucket(newBucket, logType, entry);
                    return buckets;
                }

                // Align entry time to the start of its window
                long windowStart = entryTime - (entryTime % windowSizeMs);

                // Locate or create the bucket for this window
                int index = findBucketIndex(buckets, windowStart);
                WindowBucket targetBucket;
                if (index >= 0) {
                    // Existing bucket found
                    targetBucket = buckets.get(index);
                } else {
                    // Create and insert a new bucket at the correct position
                    int insertionPoint = -index - 1;
                    targetBucket = new WindowBucket(windowStart, windowSizeMs);
                    buckets.add(insertionPoint, targetBucket);
                    log.info("Added new window bucket for IP {} at start time {}", ip, windowStart);
                }

                // Add the entry to the selected bucket
                addEntryToBucket(targetBucket, logType, entry);
                return buckets;
            });
        } catch (NullPointerException e) {
            log.error("Invalid log entry format: {}", entry, e);
            throw new LogProcessingException("Missing required fields in log entry", e);
        } catch (Exception e) {
            log.error("Failed to process log entry: {}", entry, e);
            throw new LogProcessingException("Error processing log entry", e);
        }
    }

    /**
     * Adds a log entry to a bucket's log type map in a thread-safe manner.
     */
    private void addEntryToBucket(WindowBucket bucket, String logType, JsonNode entry) {
        bucket.logEntriesByType.computeIfAbsent(logType, k -> new CopyOnWriteArrayList<>()).add(entry);
        log.debug("Added entry to bucket at {} for log type {}", bucket.windowStart, logType);
    }

    /**
     * Performs a binary search to find the bucket matching windowStart or its insertion point.
     *
     * @return Index if found, or negative insertion point if not found
     */
    private int findBucketIndex(List<WindowBucket> buckets, long windowStart) {
        int low = 0;
        int high = buckets.size() - 1;
        while (low <= high) {
            int mid = (low + high) >>> 1; // Unsigned shift to avoid overflow
            long midVal = buckets.get(mid).windowStart;
            if (midVal < windowStart) {
                low = mid + 1;
            } else if (midVal > windowStart) {
                high = mid - 1;
            } else {
                return mid; // Exact match found
            }
        }
        return -(low + 1); // Return insertion point if no match
    }

    /**
     * Periodically flushes windows older than the window size to the processing queue.
     */
    @Scheduled(fixedRateString = "${zeek.flush.rate.seconds:30}000")
    public void flushStaleWindows() {
        if (isShuttingDown) {
            log.info("Skipping stale window flush: service is shutting down");
            return;
        }
        log.info("Starting stale window cleanup");
        long cutoff = System.currentTimeMillis() - windowSizeMs;
        connectionWindows.forEach((ip, buckets) -> {
            connectionWindows.compute(ip, (k, v) -> {
                if (v == null) return null;
                int i = 0;
                // Identify and process all stale buckets
                while (i < v.size() && v.get(i).windowStart + v.get(i).windowSize < cutoff) {
                    WindowBucket staleBucket = v.get(i);
                    if (!staleBucket.logEntriesByType.isEmpty()) {
                        log.info("Flushing stale window for IP {} (start: {}, log types: {})",
                                ip, staleBucket.windowStart, staleBucket.logEntriesByType.keySet());
                        submitWindow(ip, staleBucket);
                    }
                    i++;
                }
                // Remove processed stale buckets
                if (i > 0) {
                    v.subList(0, i).clear();
                }
                // Remove the IP entry if no buckets remain
                return v.isEmpty() ? null : v;
            });
        });
        log.info("Completed stale window cleanup");
    }

    /**
     * Flushes all current windows to the processing queue, typically before shutdown.
     */
    public void flushAllWindows() {
        log.info("Flushing all current windows");
        connectionWindows.forEach((ip, buckets) -> {
            connectionWindows.compute(ip, (k, v) -> {
                if (v != null) {
                    v.forEach(bucket -> submitWindow(ip, bucket));
                    v.clear();
                }
                return null; // Clear the IP entry after flushing
            });
        });
        log.info("All windows flushed. Queue size: {}", processingQueue.size());
    }

    /**
     * Shuts down the service, clearing all resources and preventing further processing.
     */
    @PreDestroy
    public void shutdown() {
        log.info("Shutting down window processor. Cleaning up resources.");
        isShuttingDown = true;
        flushAllWindows(); // Ensure all data is processed before clearing
        processingQueue.clear();
        connectionWindows.clear();
        log.info("Shutdown complete. Queue size: {}, IP windows: {}",
                processingQueue.size(), connectionWindows.size());
    }

    /**
     * Creates a new window bucket aligned to the given timestamp.
     */
    private WindowBucket createNewBucket(long timestamp) {
        WindowBucket bucket = new WindowBucket(timestamp, windowSizeMs);
        log.debug("Created new window bucket starting at {}", bucket.windowStart);
        return bucket;
    }

    /**
     * Submits a window bucket's data to the processing queue with a copy of its entries.
     */
    private void submitWindow(String ip, WindowBucket bucket) {
        Map<String, List<JsonNode>> logEntriesCopy = new HashMap<>();
        bucket.logEntriesByType.forEach((logType, entries) -> {
            logEntriesCopy.put(logType, List.copyOf(entries)); // Immutable copy for thread safety
        });
        WindowData windowData = new WindowData(ip, bucket.windowStart, logEntriesCopy);
        if (processingQueue.offer(windowData)) {
            log.info("Submitted window for IP {} with log types {} (start: {})",
                    ip, logEntriesCopy.keySet(), bucket.windowStart);
        } else {
            log.error("Failed to submit window for IP {}: processing queue is full", ip);
        }
    }

    /**
     * Custom exception for log processing failures.
     */
    public static class LogProcessingException extends RuntimeException {
        public LogProcessingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}