package com.threat.anomalyze.commons.util;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class ZeekTimestampConverter {
    public static String toHumanReadableUtc(double timestampMs) {
        return Instant.ofEpochMilli((long) timestampMs)
                .atZone(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_DATE_TIME);
    }
}