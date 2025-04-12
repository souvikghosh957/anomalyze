package com.threat.anomalyze.commons.features;

import java.util.List;
import java.util.Map;

public class FeatureConfig {
    public static final String CONNECTION_FREQUENCY = "conn_freq";
    public static final String UNIQUE_PORTS = "unique_ports";
    public static final String CONNECTION_DURATION_AVG = "conn_duration_avg";
    public static final String PORT_ENTROPY = "port_entropy";
    public static final String CONNECTION_STATE_ENTROPY = "connection_state_entropy";
    public static final String BYTES_IN_OUT_RATIO = "bytes_in_out_ratio";
    public static final String DESTINATION_IP_ENTROPY = "destination_ip_entropy";
    public static final String UDP_TCP_RATIO = "udp_tcp_ratio";
    public static final String RARE_HTTP_METHODS = "rare_http_methods";
    public static final String URI_ANOMALIES = "uri_anomalies";
    public static final String STATUS_CODE_RATIO = "status_code_ratio";
    public static final String METHOD_FREQUENCY_SKEW = "method_frequency_skew";
    public static final String RESPONSE_CODE_ENTROPY = "response_code_entropy";
    public static final String DNS_QUERY_FREQUENCY = "dns_query_freq";
    public static final String DOMAIN_ENTROPY = "domain_entropy";
    public static final String DNS_UNIQUE_DOMAIN = "dns_unique_domains";
    public static final String QUERY_RESPONSE_TIME_AVG = "query_response_time_avg";
    public static final String DOMAIN_AGE_ANOMALY = "domain_age_anomaly";
    public static final String OUTDATED_SSL_VERSIONS = "outdated_ssl_versions";
    public static final String WEAK_CIPHERS = "weak_ciphers";
    public static final String CIPHER_SUITE_ENTROPY = "cipher_suite_entropy";
    public static final String JA3_SIMILARITY_SCORE = "ja3_similarity_score";
    public static final String NOTICE_ANOMALIES = "notice_anomalies";
    public static final String DNS_SSL_CORRELATION = "dns_ssl_correlation";
    public static final String HTTP_SSL_RATIO = "http_ssl_ratio";
    public static final String DAY_OF_WEEK_ENTROPY = "day_of_week_entropy";
    public static final String INTER_LOG_EVENT_TIMING = "inter_log_event_timing";

    public static final List<String> CSV_HEADERS = List.of(
            "timestamp", "ip",
            CONNECTION_FREQUENCY,
            UNIQUE_PORTS,
            CONNECTION_DURATION_AVG,
            PORT_ENTROPY,
            CONNECTION_STATE_ENTROPY,
            BYTES_IN_OUT_RATIO,
            DESTINATION_IP_ENTROPY,
            UDP_TCP_RATIO,
            RARE_HTTP_METHODS,
            URI_ANOMALIES,
            STATUS_CODE_RATIO,
            METHOD_FREQUENCY_SKEW,
            RESPONSE_CODE_ENTROPY,
            DNS_QUERY_FREQUENCY,
            DNS_UNIQUE_DOMAIN,
            DOMAIN_ENTROPY,
            QUERY_RESPONSE_TIME_AVG,
            DOMAIN_AGE_ANOMALY,
            OUTDATED_SSL_VERSIONS,
            WEAK_CIPHERS,
            CIPHER_SUITE_ENTROPY,
            JA3_SIMILARITY_SCORE,
            NOTICE_ANOMALIES,
            DNS_SSL_CORRELATION,
            HTTP_SSL_RATIO,
            DAY_OF_WEEK_ENTROPY,
            INTER_LOG_EVENT_TIMING
    );

    public static final long WINDOW_SIZE_MS = 60_000;
}

