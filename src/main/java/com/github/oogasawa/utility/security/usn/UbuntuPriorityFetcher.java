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

    /**
     * Fetches the severity priority assigned to a given CVE ID from the Ubuntu security tracker.
     *
     * @param cveId the CVE identifier (e.g., "CVE-2024-12345")
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
                    throw new IOException("No response entity for " + url);
                }

                try (InputStream content = entity.getContent()) {
                    return extractPriorityFromHtmlLines(content);
                }
            }
        }
    }

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

