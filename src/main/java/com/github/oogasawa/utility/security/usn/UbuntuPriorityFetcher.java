package com.github.oogasawa.utility.security.usn;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.util.Timeout;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A utility class that fetches the CVE severity level (priority) as defined on the official Ubuntu
 * security tracker web page.
 */
public class UbuntuPriorityFetcher {
    
    private static final Logger logger = LoggerFactory.getLogger(UbuntuPriorityFetcher.class);
    private static final int MAX_RETRIES = 3;
    private static final int RETRY_DELAY_MS = 2000;
    private static final int TIMEOUT_SECONDS = 30;

    /**
     * Fetches the severity priority assigned to a given CVE ID from the Ubuntu security tracker.
     * Implements retry logic with exponential backoff for network failures.
     *
     * @param cveId the CVE identifier (e.g., "CVE-2024-12345")
     * @return the extracted priority string (e.g., "Low", "High"), or "Unknown" if not found
     * @throws Exception if an error occurs during HTTP communication or parsing after all retries
     */
    public static String fetchUbuntuPriority(String cveId) throws Exception {
        String url = "https://ubuntu.com/security/" + cveId;
        
        Exception lastException = null;
        
        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                logger.debug("Fetching Ubuntu priority for {} (attempt {}/{})", cveId, attempt, MAX_RETRIES);
                
                RequestConfig requestConfig = RequestConfig.custom()
                    .setConnectionRequestTimeout(Timeout.ofSeconds(TIMEOUT_SECONDS))
                    .setResponseTimeout(Timeout.ofSeconds(TIMEOUT_SECONDS))
                    .build();
                
                try (CloseableHttpClient client = HttpClients.custom()
                        .setDefaultRequestConfig(requestConfig)
                        .build()) {
                    
                    HttpGet request = new HttpGet(url);
                    request.setHeader("User-Agent", "Mozilla/5.0 (compatible; USNChecker/1.0)");
                    
                    try (CloseableHttpResponse response = client.execute(request)) {
                        int statusCode = response.getCode();
                        
                        if (statusCode == HttpStatus.SC_NOT_FOUND) {
                            logger.warn("CVE {} not found on Ubuntu tracker (404)", cveId);
                            return "Unknown";
                        }
                        
                        if (statusCode != HttpStatus.SC_OK) {
                            throw new IOException(String.format(
                                "HTTP error %d for %s", statusCode, url));
                        }
                        
                        HttpEntity entity = response.getEntity();
                        if (entity == null) {
                            throw new IOException("No response entity for " + url);
                        }

                        try (InputStream content = entity.getContent()) {
                            String priority = extractPriorityFromHtmlLines(content);
                            logger.debug("Successfully fetched priority '{}' for {}", priority, cveId);
                            return priority;
                        }
                    }
                }
                
            } catch (Exception e) {
                lastException = e;
                logger.warn("Attempt {}/{} failed for {}: {}", 
                    attempt, MAX_RETRIES, cveId, e.getMessage());
                
                if (attempt < MAX_RETRIES) {
                    int delay = RETRY_DELAY_MS * attempt;
                    logger.debug("Retrying after {} ms...", delay);
                    Thread.sleep(delay);
                } else {
                    logger.error("All {} attempts failed for {}", MAX_RETRIES, cveId);
                }
            }
        }
        
        throw new IOException(
            String.format("Failed to fetch Ubuntu priority for %s after %d attempts", 
                cveId, MAX_RETRIES), lastException);
    }

    /**
     * Scans the Ubuntu tracker HTML response for the first occurrence of a CVE priority icon and
     * returns its textual severity representation.
     *
     * @param input response stream from the Ubuntu security tracker
     * @return priority label such as {@code Low}, {@code Medium}, {@code High}, {@code Critical}, or
     *         {@code Unknown} when no icon is found
     * @throws IOException if the response stream cannot be read
     */
    public static String extractPriorityFromHtmlLines(InputStream input) throws IOException {
        BufferedReader reader =
                new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        String line;
        Pattern pattern = Pattern.compile("CVE-Priority-icon-(Low|Medium|High|Critical)\\.svg",
                Pattern.CASE_INSENSITIVE);

        while ((line = reader.readLine()) != null) {
            Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                return matcher.group(1); // First match is assumed to be Ubuntu priority
            }
        }

        return "Unknown";
    }


}
