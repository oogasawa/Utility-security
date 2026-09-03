package com.github.oogasawa.utility.security.usn;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Issues HTTP GET requests against the security pages of ubuntu.com and returns the response body.
 *
 * <p>
 * Every request this project sends to ubuntu.com goes through this class so that the pacing rule
 * below is applied in one place. That covers the JSON endpoints of the Ubuntu Security API and the
 * HTML page of a notice alike, because the load that matters is the load on one server, not the
 * shape of the response. Splitting the rule across the callers has already caused two of them to be
 * written without it.
 * </p>
 *
 * <h2>Why requests are paced</h2>
 *
 * <p>
 * Producing a report for one week issues one request per page of notices plus one request per CVE,
 * which reaches roughly one hundred requests. Issuing them back to back makes the server answer
 * HTTP 503 and then stop answering the calling host altogether. Recovery takes an unknown amount of
 * time and blocks every later request from the same host, so the interval is a requirement of the
 * design rather than a tuning parameter.
 * </p>
 *
 * <h2>How a request is retried</h2>
 *
 * <p>
 * The endpoint that returns one CVE answers HTTP 503 and HTTP 504 from time to time, and a request
 * that fails there costs more than a slow report: the caller cannot determine the priority of that
 * CVE, so the notice referring to it is reported with an unknown severity. Giving up after a few
 * quick attempts turns a temporary server fault into a wrong report, therefore a request is
 * attempted up to {@value #MAX_RETRIES} times and the wait grows by
 * {@value #RETRY_INCREMENT_MS} milliseconds with every retry.
 * </p>
 *
 * <pre>
 * attempt  1   2   3    4    5    6    7    8    9   10
 * wait/s   3   8  13   18   23   28   33   38   43   48
 * </pre>
 *
 * <p>
 * A retry also multiplies the load exactly when the server has started refusing, and the growing
 * wait is what keeps the retries from making the refusal worse.
 * </p>
 */
public class UbuntuSecurityHttpClient {

    private static final Logger logger = LoggerFactory.getLogger(UbuntuSecurityHttpClient.class);

    /** Minimum wait before every request. */
    public static final long REQUEST_INTERVAL_MS = 3000L;

    /** Additional wait added for each retry, on top of {@link #REQUEST_INTERVAL_MS}. */
    public static final long RETRY_INCREMENT_MS = 5000L;

    /** Number of attempts made before a request is reported as failed. */
    public static final int MAX_RETRIES = 10;

    /** How long to wait for a connection to be established. */
    private static final int CONNECT_TIMEOUT_SECONDS = 30;

    /**
     * How long to wait for the response.
     *
     * <p>
     * Thirty seconds was not enough. With that limit, thirty nine of fifty one failed requests were
     * read timeouts, which means the response had not even reached the quarter of the page that
     * carries the priority. A request that times out costs the full wait and then a retry that waits
     * longer still, so waiting longer for one answer is cheaper than throwing the answer away and
     * asking again.
     * </p>
     */
    private static final int RESPONSE_TIMEOUT_SECONDS = 120;

    private static final String USER_AGENT = "Mozilla/5.0 (compatible; USNChecker/1.0)";

    /**
     * Reads the lines of a response as they arrive.
     */
    public interface LineScanner {

        /**
         * Examines one line of the response.
         *
         * @param line the line, without its line separator
         * @return true when enough has been read and the rest of the body can be dropped
         */
        boolean scan(String line);
    }

    /** Turns the content of a response into the value the caller asked for. */
    private interface ResponseReader<T> {
        T read(java.io.InputStream content) throws IOException;
    }

    /**
     * Requests the given URL and returns the response body as JSON.
     *
     * @param url the absolute URL to request
     * @return the response body, or {@code null} when the server answers HTTP 404
     * @throws IOException if the request does not succeed within {@value #MAX_RETRIES} attempts
     */
    public static String fetchJson(String url) throws IOException {
        return fetchBody(url, "application/json");
    }

    /**
     * Requests the given URL and returns the whole response body.
     *
     * @param url the absolute URL to request
     * @param acceptHeader the value of the {@code Accept} request header
     * @return the response body, or {@code null} when the server answers HTTP 404
     * @throws IOException if the request does not succeed within {@value #MAX_RETRIES} attempts
     */
    public static String fetchBody(String url, String acceptHeader) throws IOException {
        return fetchWithRetries(url, acceptHeader,
                content -> new String(content.readAllBytes(), StandardCharsets.UTF_8));
    }

    /**
     * Requests the given URL and hands the response to the scanner line by line, stopping as soon
     * as the scanner says it has read enough.
     *
     * <p>
     * The page of a CVE is about eighty five kilobytes and carries the priority a quarter of the
     * way in. Reading the whole body before looking at it meant that a response which stalled
     * after the priority had already arrived was thrown away and counted as a failure, even though
     * the wanted value was in hand. Stopping at the wanted line drops three quarters of the
     * transfer and removes that class of failure.
     * </p>
     *
     * @param url the absolute URL to request
     * @param acceptHeader the value of the {@code Accept} request header
     * @param scanner examines each line and says when to stop
     * @return true when the page was read, false when the server answered HTTP 404
     * @throws IOException if the request does not succeed within {@value #MAX_RETRIES} attempts
     */
    public static boolean fetchLines(String url, String acceptHeader, LineScanner scanner)
            throws IOException {

        if (scanner == null) {
            throw new IllegalArgumentException("Scanner must not be null");
        }

        Boolean read = fetchWithRetries(url, acceptHeader, content -> {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(content, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                if (scanner.scan(line)) {
                    return Boolean.TRUE;
                }
            }
            return Boolean.TRUE;
        });
        return read != null;
    }

    /**
     * Requests the given URL and turns the response into a value, retrying on failure.
     *
     * <p>
     * The caller waits {@link #REQUEST_INTERVAL_MS} before the first attempt, and that interval
     * multiplied by the attempt number before each retry.
     * </p>
     *
     * @param <T> the type of the value read from the response
     * @param url the absolute URL to request
     * @param acceptHeader the value of the {@code Accept} request header
     * @param responseReader turns the content of the response into the value
     * @return the value, or {@code null} when the server answers HTTP 404
     * @throws IOException if the request does not succeed within {@value #MAX_RETRIES} attempts
     */
    private static <T> T fetchWithRetries(String url, String acceptHeader,
            ResponseReader<T> responseReader) throws IOException {

        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("URL must not be null or blank");
        }

        Exception lastException = null;

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            waitBeforeRequest(attempt);

            try {
                logger.debug("Requesting {} (attempt {}/{})", url, attempt, MAX_RETRIES);

                RequestConfig requestConfig = RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofSeconds(CONNECT_TIMEOUT_SECONDS))
                        .setResponseTimeout(Timeout.ofSeconds(RESPONSE_TIMEOUT_SECONDS))
                        .build();

                try (CloseableHttpClient client = HttpClients.custom()
                        .setDefaultRequestConfig(requestConfig)
                        .build()) {

                    HttpGet request = new HttpGet(url);
                    request.setHeader("User-Agent", USER_AGENT);
                    request.setHeader("Accept", acceptHeader);

                    try (CloseableHttpResponse response = client.execute(request)) {
                        int statusCode = response.getCode();

                        if (statusCode == HttpStatus.SC_NOT_FOUND) {
                            logger.warn("The server answered HTTP 404 for {}", url);
                            return null;
                        }
                        if (statusCode != HttpStatus.SC_OK) {
                            throw new IOException(
                                    String.format("HTTP error %d for %s", statusCode, url));
                        }

                        HttpEntity entity = response.getEntity();
                        if (entity == null) {
                            throw new IOException("No response entity for " + url);
                        }
                        try (java.io.InputStream content = entity.getContent()) {
                            return responseReader.read(content);
                        }
                    }
                }

            } catch (IOException e) {
                lastException = e;
                logger.warn("Attempt {}/{} failed for {}: {}",
                        attempt, MAX_RETRIES, url, e.getMessage());
            } catch (Exception e) {
                lastException = e;
                logger.warn("Attempt {}/{} failed for {}: {} ({})",
                        attempt, MAX_RETRIES, url, e.getMessage(), e.getClass().getSimpleName());
            }
        }

        throw new IOException(
                String.format("Failed to fetch %s after %d attempts", url, MAX_RETRIES),
                lastException);
    }

    /**
     * Waits before issuing a request.
     *
     * @param attempt the attempt number, counting from one
     * @throws IOException if the thread is interrupted while waiting
     */
    private static void waitBeforeRequest(int attempt) throws IOException {
        try {
            Thread.sleep(waitMillisBefore(attempt));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting between requests", e);
        }
    }

    /**
     * Returns how long to wait before the given attempt.
     *
     * @param attempt the attempt number, counting from one
     * @return the wait in milliseconds
     */
    static long waitMillisBefore(int attempt) {
        return REQUEST_INTERVAL_MS + RETRY_INCREMENT_MS * (attempt - 1);
    }
}
