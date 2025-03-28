package com.threat.anomalyze.commons.features;

import java.util.List;

public class FeatureConfig {
    public static final List<String> CSV_HEADERS = List.of(
            "timestamp",
            "ip",
            "conn_freq",
            "unique_ports",
            "conn_duration_avg",
            "port_entropy",
            "rare_http_methods",
            "uri_anomalies",
            "status_code_ratio",
            "dns_query_freq",
            "domain_entropy",
            "outdated_ssl_versions",
            "weak_ciphers",
            "notice_anomalies"
    );

    public static final long WINDOW_SIZE_MS = 60_000;
}
