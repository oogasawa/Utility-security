package com.github.oogasawa.utility.security.usn;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpEntity;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * A utility class that fetches the CVE severity level (priority) as defined on the official Ubuntu
 * security tracker web page.
 */
public class UbuntuPriorityFetcher {

    /**
     * Fetches the severity priority assigned to a given CVE ID from the Ubuntu security tracker.
     *
     * @param cveId the CVE identifier (e.g., "CVE-2024-12345")
     * @return the extracted priority string (e.g., "Low", "High"), or "Unknown" if not found
     * @throws Exception if an error occurs during HTTP communication or parsing
     */
    public static String fetchUbuntuPriority(String cveId) throws Exception {
        String url = "https://ubuntu.com/security/" + cveId;
        String html = downloadHtml(url);
        return extractPriority(html);
    }

    /**
     * Downloads the HTML content of the specified URL.
     *
     * @param url the URL to fetch
     * @return the HTML content as a string
     * @throws Exception if any network or I/O error occurs
     */
    private static String downloadHtml(String url) throws Exception {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);

            try (CloseableHttpResponse response = client.execute(request)) {
                HttpEntity entity = response.getEntity();
                if (entity == null) {
                    throw new RuntimeException("No response entity for URL: " + url);
                }

                try (InputStream in = entity.getContent();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {

                    StringBuilder html = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        html.append(line).append("\n");
                    }
                    return html.toString();
                }
            }
        }
    }

    /**
     * Parses the HTML and extracts the Ubuntu priority from the correct DOM section.
     *
     * @param html the HTML content to parse
     * @return the priority string if found, otherwise "Unknown"
     */
    private static String extractPriority(String html) {
        Document doc = Jsoup.parse(html);

        for (Element label : doc.select("p.p-text--small-caps")) {
            if (label.text().trim().equalsIgnoreCase("Ubuntu priority")) {
                Element container = label.closest("div");  // safer than parent() for nesting
                if (container != null) {
                    Element strong = container.selectFirst("strong");
                    if (strong != null) {
                        return strong.text().trim();
                    }
                }
            }
        }

        return "Unknown";
    }
}

