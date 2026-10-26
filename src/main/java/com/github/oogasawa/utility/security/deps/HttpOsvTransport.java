package com.github.oogasawa.utility.security.deps;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Sends requests to api.osv.dev, waiting at least {@value #INTERVAL_MS} ms between requests.
 */
public class HttpOsvTransport implements OsvTransport {

    /** Minimum wait before every request. */
    public static final long INTERVAL_MS = 3000L;

    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(30))
            .build();

    @Override
    public String post(String url, String json) throws IOException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(120))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        return send(req);
    }

    @Override
    public String get(String url) throws IOException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(120))
                .GET()
                .build();
        return send(req);
    }

    private String send(HttpRequest req) throws IOException {
        try {
            Thread.sleep(INTERVAL_MS);
            HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() == 404) {
                return null;
            }
            if (res.statusCode() != 200) {
                throw new IOException("OSV answered HTTP " + res.statusCode() + " for " + req.uri());
            }
            return res.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted", e);
        }
    }
}
