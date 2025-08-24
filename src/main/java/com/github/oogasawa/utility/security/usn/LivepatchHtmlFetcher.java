package com.github.oogasawa.utility.security.usn;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketTimeoutException;

/**
 * A utility class to fetch the HTML document for a given USN ID
 * from the Ubuntu Security Notices website.
 */
public class LivepatchHtmlFetcher {
    
    private static final Logger logger = LoggerFactory.getLogger(LivepatchHtmlFetcher.class);
    private static final int MAX_RETRIES = 3;
    private static final int TIMEOUT_MS = 30_000;

    /**
     * Fetches the HTML Document of the given USN ID from https://ubuntu.com/security/notices/.
     * Implements retry logic for network failures.
     *
     * @param usnId e.g., "USN-7513-1"
     * @return the parsed Document object from the USN web page
     * @throws IOException if connection or parsing fails after all retries
     * @throws IllegalArgumentException if usnId is null or empty
     */
    public static Document fetchUsnDocument(String usnId) throws IOException {
        if (usnId == null || usnId.trim().isEmpty()) {
            throw new IllegalArgumentException("USN ID cannot be null or empty");
        }
        String url = "https://ubuntu.com/security/notices/" + usnId.trim();
        IOException lastException = null;
        
        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                logger.debug("Fetching USN document for {} (attempt {}/{})", usnId, attempt, MAX_RETRIES);
                
                Document doc = Jsoup.connect(url)
                        .userAgent("Mozilla/5.0 (compatible; USNChecker/1.0)")
                        .timeout(TIMEOUT_MS)
                        .ignoreHttpErrors(false)
                        .get();
                
                logger.debug("Successfully fetched USN document for {}", usnId);
                return doc;
                
            } catch (SocketTimeoutException e) {
                lastException = new IOException(
                    String.format("Timeout while fetching %s (attempt %d/%d)", 
                        url, attempt, MAX_RETRIES), e);
                logger.warn("Timeout fetching {} (attempt {}/{}): {}", 
                    usnId, attempt, MAX_RETRIES, e.getMessage());
                    
            } catch (IOException e) {
                lastException = e;
                logger.warn("Failed to fetch {} (attempt {}/{}): {}", 
                    usnId, attempt, MAX_RETRIES, e.getMessage());
            }
            
            if (attempt < MAX_RETRIES) {
                int delay = 2000 * attempt;
                logger.debug("Retrying after {} ms...", delay);
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted while retrying", ie);
                }
            }
        }
        
        logger.error("Failed to fetch USN document for {} after {} attempts", usnId, MAX_RETRIES);
        throw new IOException(
            String.format("Failed to fetch USN document for %s after %d attempts", 
                usnId, MAX_RETRIES), lastException);
    }
} 
