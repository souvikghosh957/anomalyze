package com.threat.anomalyze.commons.services;

import com.google.common.net.InternetDomainName;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.net.whois.WhoisClient;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@Slf4j
public class WhoisService {
    private static final Map<String, LocalDateTime> cache = new ConcurrentHashMap<>();
    private static final int SOCKET_TIMEOUT_MS = 5000; // 5 seconds timeout
    private static final LocalDateTime DEFAULT_DATE = LocalDateTime.now().minusYears(1); // Fallback date
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");

    // Patterns for extracting creation date from WHOIS response
    private static final Pattern[] CREATION_DATE_PATTERNS = {
            Pattern.compile("Creation Date: (\\d{4}-\\d{2}-\\d{2})"),
            Pattern.compile("Registered on: (\\d{4}-\\d{2}-\\d{2})"),
            Pattern.compile("Domain Create Date: (\\d{4}-\\d{2}-\\d{2})"),
            Pattern.compile("Created: (\\d{4}-\\d{2}-\\d{2})"),
            Pattern.compile("Registration Date: (\\d{4}-\\d{2}-\\d{2})")
    };

    /**
     * Retrieves the creation date of a domain using WHOIS.
     * Returns a default date (1 year ago) if the domain is unrecognized or WHOIS fails.
     *
     * @param domain The domain or subdomain to look up.
     * @return The creation date as LocalDateTime, or null if the domain is invalid.
     */
    public static LocalDateTime getWhoisCreationDate(String domain) {
        // Handle special case for "*"
        if ("*".equals(domain)) {
            return DEFAULT_DATE;
        }

        // Validate domain format
        if (!isValidDomain(domain)) {
            log.warn("Invalid domain format: {}", domain);
            return DEFAULT_DATE;
        }

        // Get top private domain
        String topPrivateDomain = getTopPrivateDomain(domain);
        if (topPrivateDomain == null) {
            log.warn("No recognized public suffix for domain: {}", domain);
            return DEFAULT_DATE; // Fallback for unrecognized suffixes
        }

        // Check cache
        if (cache.containsKey(topPrivateDomain)) {
            return cache.get(topPrivateDomain);
        }

        // Perform WHOIS query
        WhoisClient whoisClient = new WhoisClient();
        whoisClient.setDefaultTimeout(SOCKET_TIMEOUT_MS);
        whoisClient.setConnectTimeout(SOCKET_TIMEOUT_MS);

        try {
            whoisClient.connect(WhoisClient.DEFAULT_HOST);
            String whoisData = whoisClient.query(topPrivateDomain);
            whoisClient.disconnect();

            // Extract creation date
            LocalDateTime creationDate = extractCreationDate(whoisData);
            if (creationDate != null) {
                log.info("Creation date for {}: {}", topPrivateDomain, creationDate);
                cache.put(topPrivateDomain, creationDate);
                return creationDate;
            } else {
                log.warn("No creation date found for: {}", topPrivateDomain);
                cache.put(topPrivateDomain, DEFAULT_DATE);
                return DEFAULT_DATE;
            }
        } catch (IOException e) {
            log.warn("WHOIS query failed for {}: {}", topPrivateDomain, e.getMessage());
            cache.put(topPrivateDomain, DEFAULT_DATE);
            return DEFAULT_DATE;
        }
    }

    /**
     * Validates the domain format using a regex pattern.
     *
     * @param domain The domain to validate.
     * @return True if valid, false otherwise.
     */
    private static boolean isValidDomain(String domain) {
        if (domain == null || domain.trim().isEmpty()) {
            return false;
        }
        return DOMAIN_PATTERN.matcher(domain.trim()).matches();
    }

    /**
     * Extracts the top private domain using Guava's InternetDomainName.
     *
     * @param domain The domain to process.
     * @return The top private domain, or null if invalid or unrecognized.
     */
    private static String getTopPrivateDomain(String domain) {
        try {
            String cleanedDomain = domain.trim().replaceAll("\\.$", "");
            InternetDomainName domainName = InternetDomainName.from(cleanedDomain);
            return domainName.topPrivateDomain().toString();
        } catch (IllegalArgumentException | IllegalStateException e) {
            log.warn("Failed to extract top private domain for {}: {}", domain, e.getMessage());
            return null; // Handle invalid domains or unrecognized suffixes
        }
    }

    /**
     * Extracts the creation date from WHOIS data.
     *
     * @param whoisData The WHOIS response string.
     * @return The parsed creation date, or null if not found.
     */
    private static LocalDateTime extractCreationDate(String whoisData) {
        for (Pattern pattern : CREATION_DATE_PATTERNS) {
            Matcher matcher = pattern.matcher(whoisData);
            if (matcher.find()) {
                String dateStr = matcher.group(1);
                try {
                    return LocalDateTime.parse(dateStr + "T00:00:00", DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                } catch (Exception ignored) {
                    // Ignore parsing errors
                }
            }
        }
        return null;
    }
}