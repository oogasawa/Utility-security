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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A utility class that fetches the CVE severity level (priority) as defined on the official
 * Ubuntu security tracker web page.
 * <p>
 * This class retrieves the priority string (e.g., "Low", "Medium", "High", "Critical") by parsing
 * the CVE detail page at {@code https://ubuntu.com/security/<CVE-ID>}.
 */
public class UbuntuPriorityFetcher {

    /**
     * A regular expression pattern used to detect priority labels in HTML content.
     * Example match: {@code <strong>High</strong>}
     */
    private static final Pattern PRIORITY_PATTERN = Pattern.compile("<strong>(Low|Medium|High|Critical)</strong>");

    /**
     * Fetches the severity priority assigned to a given CVE ID from the Ubuntu security tracker.
     * <p>
     * This method makes an HTTP GET request to the CVE-specific page on ubuntu.com, and attempts
     * to extract the priority level by scanning for a known HTML pattern. If the pattern is not
     * matched in the first {@code maxLines} lines, it falls back to parsing the HTML with Jsoup
     * to look for a specific element.
     *
     * @param cveId the CVE identifier (e.g., {@code CVE-2024-12345})
     * @return the extracted priority string (e.g., "Low", "High"), or "Unknown" if not found
     * @throws Exception if an error occurs during HTTP communication or parsing
     */
    public static String fetchUbuntuPriority(String cveId) throws Exception {
        String url = "https://ubuntu.com/security/" + cveId;

        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);

            try (CloseableHttpResponse response = client.execute(request)) {
                HttpEntity entity = response.getEntity();
                if (entity == null) {
                    throw new RuntimeException("No response entity for URL: " + url);
                }

                try (InputStream in = entity.getContent();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {

                    String line;
                    StringBuilder headFragment = new StringBuilder();
                    int linesRead = 0;
                    final int maxLines = 3000; // Limit the number of lines read to prevent excessive memory use

                    // Attempt to find the priority pattern directly while reading the response
                    while ((line = reader.readLine()) != null && linesRead++ < maxLines) {
                        headFragment.append(line).append("\n");
                        Matcher m = PRIORITY_PATTERN.matcher(line);
                        if (m.find()) {
                            return m.group(1);
                        }
                    }

                    // Fallback: use Jsoup to parse the collected fragment and locate the priority element
                    Document doc = Jsoup.parse(headFragment.toString());
                    Element el = doc.selectFirst("div.cve-hero-scores strong");
                    return el != null ? el.text().trim() : "Unknown";
                }
            }
        }
    }

}

