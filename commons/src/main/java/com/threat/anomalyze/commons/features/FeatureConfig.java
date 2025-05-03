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
    public static final String UDP_RATIO = "udp_ratio";
    public static final String TCP_RATIO = "tcp_ratio";
    public static final String ICMP_RATIO = "icmp_ratio";
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
    public static final String WEAK_CURVE_COUNT = "weak_curve_count";
    public static final String RESUMPTION_RATE = "resumption_rate";
    public static final String NEXT_PROTOCOL_ENTROPY = "next_protocol_entropy";
    public static final String NOTICE_COUNT = "notice_count";
    public static final String NOTICE_TYPE_ENTROPY = "notice_type_entropy";
    public static final String AVERAGE_SEVERITY = "average_severity";
    public static final String NOTICE_RATE = "notice_rate";
    public static final String NOTICE_TIMESTAMP_VARIANCE = "notice_timestamp_variance";
    public static final String CONNECTION_RATE = "connection_rate";
    public static final String INCOMPLETE_CONNECTION_RATIO = "incomplete_connection_ratio";
    public static final String NXDOMAIN_RATIO = "nxdomain_ratio";
    public static final String QUERY_LENGTH_ENTROPY = "query_length_entropy";
    public static final String SUBDOMAIN_LEVEL_AVG = "subdomain_level_avg";
    public static final String CLIENT_ERROR_RATIO = "client_error_ratio";
    public static final String SERVER_ERROR_RATIO = "server_error_ratio";
    public static final String METHOD_ENTROPY = "method_entropy";
    public static final String USER_AGENT_ENTROPY = "user_agent_entropy";
    public static final String BODY_LENGTH_VARIANCE = "body_length_variance";
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
    public static final String SOURCE_IP_ENTROPY = "source_ip_entropy";
    public static final String CONNECTION_TIMESTAMP_VARIANCE = "connection_timestamp_variance";
    public static final String FAILED_TS_VARIANCE = "failed_ts_variance";
    public static final String SUCCESS_LOGIN_RATIO = "success_login_ratio";
    public static final String PROTOCOL_ENTROPY = "protocol_entropy";
    public static final String FILE_UPLOAD_RATIO = "file_upload_ratio";
    public static final String SUSPICIOUS_TYPE_RATIO = "suspicious_type_ratio";
    public static final String FILE_TS_VARIANCE = "file_ts_variance";
    public static final String AUTH_ERROR_RATIO = "auth_error_ratio";
    public static final String HOST_ENTROPY = "host_entropy";
    public static final String HTTP_TIMESTAMP_VARIANCE = "http_timestamp_variance";
    public static final String URI_LENGTH_VARIANCE = "uri_length_variance";
    public static final String SSH_OUTGOING_CONNECTIONS = "ssh_outgoing_connections";
    public static final String SSH_UNIQUE_DEST_IPS = "ssh_unique_dest_ips";
    public static final String SSH_AUTH_SUCCESS_RATIO = "ssh_auth_success_ratio";
    public static final String SSH_SERVER_SOFTWARE_ENTROPY = "ssh_server_software_entropy";
    public static final String SSH_WEAK_ALGO_COUNT = "ssh_weak_algo_count";
    public static final String SSH_AVG_AUTH_ATTEMPTS = "ssh_avg_auth_attempts";
    public static final String SSH_UNIQUE_DEST_PORTS = "ssh_unique_dest_ports";
    public static final String SSH_NON_STANDARD_PORT_COUNT = "ssh_non_standard_port_count";
    public static final String SSH_TIMESTAMP_VARIANCE = "ssh_timestamp_variance";
    public static final String SSH_AVG_DURATION = "ssh_avg_duration";
    public static final String SSH_TOTAL_BYTES = "ssh_total_bytes";
    public static final String SSH_CIPHER_ALGO_ENTROPY = "ssh_cipher_algo_entropy";
    public static final String SSH_HASSH_ENTROPY = "ssh_hassh_entropy";
    public static final String SSH_INBOUND_CONNECTIONS = "ssh_inbound_connections";
    public static final String SSH_UNIQUE_SRC_IPS = "ssh_unique_src_ips";
    public static final String SSH_INBOUND_AUTH_SUCCESS_RATIO = "ssh_inbound_auth_success_ratio";
    public static final String SSH_CLIENT_SOFTWARE_ENTROPY = "ssh_client_software_entropy";
    public static final String SSH_INBOUND_WEAK_ALGO_COUNT = "ssh_inbound_weak_algo_count";
    public static final String SSH_INBOUND_AVG_AUTH_ATTEMPTS = "ssh_inbound_avg_auth_attempts";
    public static final String SSH_HASSH_SERVER_ENTROPY = "ssh_hassh_server_entropy";
    public static final String SSH_NO_CLIENT_ID_COUNT = "ssh_no_client_id_count";

    public static final List<String> CSV_HEADERS = List.of(
            "timestamp", "ip",
            CONNECTION_FREQUENCY,
            UNIQUE_PORTS,
            CONNECTION_DURATION_AVG,
            PORT_ENTROPY,
            CONNECTION_STATE_ENTROPY,
            BYTES_IN_OUT_RATIO,
            DESTINATION_IP_ENTROPY,
            SOURCE_IP_ENTROPY,
            UDP_RATIO,
            TCP_RATIO,
            ICMP_RATIO,
            CONNECTION_RATE,
            INCOMPLETE_CONNECTION_RATIO,
            CONNECTION_TIMESTAMP_VARIANCE,
            DNS_QUERY_FREQUENCY,
            DNS_UNIQUE_DOMAIN,
            DOMAIN_ENTROPY,
            QUERY_RESPONSE_TIME_AVG,
            DOMAIN_AGE_ANOMALY,
            NXDOMAIN_RATIO,
            QUERY_LENGTH_ENTROPY,
            SUBDOMAIN_LEVEL_AVG,
            RARE_HTTP_METHODS,
            URI_ANOMALIES,
            URI_LENGTH_VARIANCE,
            CLIENT_ERROR_RATIO,
            SERVER_ERROR_RATIO,
            AUTH_ERROR_RATIO,
            METHOD_ENTROPY,
            USER_AGENT_ENTROPY,
            BODY_LENGTH_VARIANCE,
            HOST_ENTROPY,
            HTTP_TIMESTAMP_VARIANCE,
            OUTDATED_SSL_VERSIONS,
            WEAK_CIPHERS,
            CIPHER_SUITE_ENTROPY,
            JA3_ENTROPY,
            SELF_SIGNED_CERT_COUNT,
            HANDSHAKE_FAILURE_RATE,
            SSL_VERSION_ENTROPY,
            WEAK_CURVE_COUNT,
            RESUMPTION_RATE,
            NEXT_PROTOCOL_ENTROPY,
            NOTICE_COUNT,
            NOTICE_TYPE_ENTROPY,
            AVERAGE_SEVERITY,
            NOTICE_RATE,
            NOTICE_TIMESTAMP_VARIANCE,
            FILE_TYPE_ENTROPY,
            AVG_FILE_SIZE,
            EXE_RATIO,
            SUSPICIOUS_TYPE_RATIO,
            UNIQUE_HASH_COUNT,
            FILE_RATE,
            PROTOCOL_ENTROPY,
            FILE_UPLOAD_RATIO,
            FILE_SIZE_VARIANCE,
            UNIQUE_SOURCE_IP_COUNT,
            FAILED_LOGIN_RATIO,
            USERNAME_ENTROPY,
            ATTEMPT_RATE,
            FAILED_TS_VARIANCE,
            SSH_OUTGOING_CONNECTIONS,
            SSH_UNIQUE_DEST_IPS,
            SSH_AUTH_SUCCESS_RATIO,
            SSH_SERVER_SOFTWARE_ENTROPY,
            SSH_WEAK_ALGO_COUNT,
            SSH_AVG_AUTH_ATTEMPTS,
            SSH_UNIQUE_DEST_PORTS,
            SSH_NON_STANDARD_PORT_COUNT,
            SSH_TIMESTAMP_VARIANCE,
            SSH_AVG_DURATION,
            SSH_TOTAL_BYTES,
            SSH_CIPHER_ALGO_ENTROPY,
            SSH_HASSH_ENTROPY,
            SSH_INBOUND_CONNECTIONS,
            SSH_UNIQUE_SRC_IPS,
            SSH_INBOUND_AUTH_SUCCESS_RATIO,
            SSH_CLIENT_SOFTWARE_ENTROPY,
            SSH_INBOUND_WEAK_ALGO_COUNT,
            SSH_INBOUND_AVG_AUTH_ATTEMPTS,
            SSH_HASSH_SERVER_ENTROPY,
            SSH_NO_CLIENT_ID_COUNT
    );

    public static final long WINDOW_SIZE_MS = 60_000;
}