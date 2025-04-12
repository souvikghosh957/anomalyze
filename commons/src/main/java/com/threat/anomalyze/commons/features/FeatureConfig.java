package com.threat.anomalyze.commons.features;

import java.util.List;

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
    public static final String DNS_QUERY_FREQUENCY = "dns_query_freq";
    public static final String DOMAIN_ENTROPY = "domain_entropy";
    public static final String DNS_UNIQUE_DOMAIN = "dns_unique_domains";
    public static final String QUERY_RESPONSE_TIME_AVG = "query_response_time_avg";
    public static final String DOMAIN_AGE_ANOMALY = "domain_age_anomaly";
    public static final String OUTDATED_SSL_VERSIONS = "outdated_ssl_versions";
    public static final String WEAK_CIPHERS = "weak_ciphers";
    public static final String CIPHER_SUITE_ENTROPY = "cipher_suite_entropy";
    public static final String JA3_ENTROPY = "ja3_entropy";
    public static final String SELF_SIGNED_CERT_COUNT = "self_signed_cert_count";
    public static final String HANDSHAKE_FAILURE_RATE = "handshake_failure_rate";
    public static final String SSL_VERSION_ENTROPY = "ssl_version_entropy";
    public static final String NOTICE_COUNT = "notice_count";
    public static final String NOTICE_TYPE_ENTROPY = "notice_type_entropy";
    public static final String AVERAGE_SEVERITY = "average_severity";
    public static final String NOTICE_RATE = "notice_rate";
    public static final String TIMESTAMP_VARIANCE = "timestamp_variance";
    public static final String CONNECTION_RATE = "connection_rate";
    public static final String SYN_FLOOD_RATIO = "syn_flood_ratio";
    public static final String NXDOMAIN_RATIO = "nxdomain_ratio";
    public static final String QUERY_LENGTH_ENTROPY = "query_length_entropy";
    public static final String SUBDOMAIN_LEVEL_AVG = "subdomain_level_avg";
    public static final String HEADER_ANOMALY_COUNT = "header_anomaly_count";
    public static final String CLIENT_ERROR_RATIO = "client_error_ratio";
    public static final String SERVER_ERROR_RATIO = "server_error_ratio";
    public static final String METHOD_ENTROPY = "method_entropy";
    public static final String USER_AGENT_ENTROPY = "user_agent_entropy";
    public static final String BODY_LENGTH_ENTROPY = "body_length_variance";
    public static final String FILE_TYPE_ENTROPY = "file_type_entropy";
    public static final String FILE_RATE = "file_rate";
    public static final String EXE_RATIO = "exe_ratio";
    public static final String UNIQUE_HASH_COUNT = "unique_hash_count";
    public static final String AVG_FILE_SIZE = "avg_file_size";
    public static final String FILE_SIZE_VARIANCE = "file_size_variance";
    public static final String FAILED_LOGIN_RATIO = "failed_login_ratio";
    public static final String USERNAME_ENTROPY = "username_entropy";
    public static final String ATTEMPT_RATE = "attempt_rate";
    public static final String UNIQUE_SOURCE_IP_COUNT = "unique_source_ip_count";
    public static final String FAILED_TS_VARIANCE = "failed_ts_variance";
    public static final String SUCCESS_LOGIN_RATIO = "success_login_ratio";
    public static final String PROTOCOL_ENTROPY = "protocol_entropy";
    public static final String FILE_UPLOAD_RATIO = "file_upload_ratio";


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
            CONNECTION_RATE,
            SSL_VERSION_ENTROPY,
            SYN_FLOOD_RATIO,
            RARE_HTTP_METHODS,
            URI_ANOMALIES,
            HEADER_ANOMALY_COUNT,
            CLIENT_ERROR_RATIO,
            SERVER_ERROR_RATIO,
            METHOD_ENTROPY,
            USER_AGENT_ENTROPY,
            BODY_LENGTH_ENTROPY,
            DNS_QUERY_FREQUENCY,
            DNS_UNIQUE_DOMAIN,
            DOMAIN_ENTROPY,
            QUERY_RESPONSE_TIME_AVG,
            DOMAIN_AGE_ANOMALY,
            NXDOMAIN_RATIO,
            QUERY_LENGTH_ENTROPY,
            SUBDOMAIN_LEVEL_AVG,
            OUTDATED_SSL_VERSIONS,
            WEAK_CIPHERS,
            CIPHER_SUITE_ENTROPY,
            JA3_ENTROPY,
            SELF_SIGNED_CERT_COUNT,
            HANDSHAKE_FAILURE_RATE,
            NOTICE_COUNT,
            NOTICE_TYPE_ENTROPY,
            AVERAGE_SEVERITY,
            NOTICE_RATE,
            TIMESTAMP_VARIANCE,
            FILE_TYPE_ENTROPY,
            AVG_FILE_SIZE,
            EXE_RATIO,
            UNIQUE_HASH_COUNT,
            FILE_RATE,
            UNIQUE_SOURCE_IP_COUNT,
            FAILED_LOGIN_RATIO,
            USERNAME_ENTROPY,
            ATTEMPT_RATE,
            FAILED_TS_VARIANCE,
            PROTOCOL_ENTROPY,
            FILE_UPLOAD_RATIO
    );

    public static final long WINDOW_SIZE_MS = 60_000;
}

