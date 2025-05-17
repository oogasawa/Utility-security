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

public class UbuntuPriorityFetcher {

    // パターン例: <strong>High</strong>
    private static final Pattern PRIORITY_PATTERN = Pattern.compile("<strong>(Low|Medium|High|Critical)</strong>");

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
                    final int maxLines = 3000; // 読み過ぎ防止のため、最大行数制限

                    while ((line = reader.readLine()) != null && linesRead++ < maxLines) {
                        headFragment.append(line).append("\n");
                        Matcher m = PRIORITY_PATTERN.matcher(line);
                        if (m.find()) {
                            return m.group(1);
                        }
                    }

                    // パターンが見つからなければ fallback として head 部分全体を Jsoup 解析
                    Document doc = Jsoup.parse(headFragment.toString());
                    Element el = doc.selectFirst("div.cve-hero-scores strong");
                    return el != null ? el.text().trim() : "Unknown";
                }
            }
        }
    }


}
