package com.github.oogasawa.utility.security.usn;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.io.IOException;

/**
 * A utility class to fetch the HTML document for a given USN ID
 * from the Ubuntu Security Notices website.
 */
public class LivepatchHtmlFetcher {

    /**
     * Fetches the HTML Document of the given USN ID from https://ubuntu.com/security/notices/.
     *
     * @param usnId e.g., "USN-7513-1"
     * @return the parsed Document object from the USN web page
     * @throws IOException if connection or parsing fails
     */
    public static Document fetchUsnDocument(String usnId) throws IOException {
        String url = "https://ubuntu.com/security/notices/" + usnId;
        return Jsoup.connect(url)
                .userAgent("Mozilla/5.0 (compatible; USNChecker/1.0)")
                .timeout(15_000)
                .get();
    }
} 
