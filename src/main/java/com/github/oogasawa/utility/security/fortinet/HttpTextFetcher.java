package com.github.oogasawa.utility.security.fortinet;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Fetches pages of fortiguard.fortinet.com, waiting at least {@value #INTERVAL_MS} ms between
 * requests.
 */
public class HttpTextFetcher implements TextFetcher {

    /** Minimum wait before every request. */
    public static final long INTERVAL_MS = 3000L;

    private final long intervalMs;

    /** Creates a fetcher that waits {@value #INTERVAL_MS} ms before every request. */
    public HttpTextFetcher() {
        this(INTERVAL_MS);
    }

    /**
     * Creates a fetcher with the given wait.
     *
     * @param intervalMs the wait before every request, in milliseconds
     */
    public HttpTextFetcher(long intervalMs) {
        this.intervalMs = intervalMs;
    }

    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(30))
            .build();

    @Override
    public String get(String url) throws IOException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(120))
                .header("User-Agent", "Mozilla/5.0 (compatible; Utility-security)")
                .GET()
                .build();
        try {
            Thread.sleep(intervalMs);
            HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() != 200) {
                throw new IOException("HTTP " + res.statusCode() + " for " + url);
            }
            return res.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted", e);
        }
    }
}
