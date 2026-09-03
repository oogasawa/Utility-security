package com.github.oogasawa.utility.security.usn;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * Fetches the HTML page of a given USN from the Ubuntu Security Notices website.
 *
 * <p>
 * Only the path that reads a file of mailing list digests uses this class. That path has no update
 * instructions of its own, so it reads them from the page of each notice. The path that reads the
 * Ubuntu Security API takes the same text from the {@code instructions} field of the response and
 * issues no request here.
 * </p>
 *
 * <p>
 * The request goes through {@link UbuntuSecurityHttpClient} so that it is paced like every other
 * request this project sends to ubuntu.com. Before that, this class called jsoup directly and left
 * no interval between two notices, which is one of the two places that made the server refuse this
 * host.
 * </p>
 */
public class LivepatchHtmlFetcher {

    private static final Logger logger = LoggerFactory.getLogger(LivepatchHtmlFetcher.class);

    private static final String NOTICE_URL_PREFIX = "https://ubuntu.com/security/notices/";

    /**
     * Fetches the HTML page of the given USN.
     *
     * @param usnId the USN identifier, for example {@code USN-7513-1}
     * @return the parsed page
     * @throws IOException if the page cannot be obtained after all retries, or if the server
     *         answers HTTP 404
     * @throws IllegalArgumentException if the identifier is null or blank
     */
    public static Document fetchUsnDocument(String usnId) throws IOException {

        if (usnId == null || usnId.isBlank()) {
            throw new IllegalArgumentException("USN ID must not be null or empty");
        }

        String url = NOTICE_URL_PREFIX + usnId.trim();
        String html = UbuntuSecurityHttpClient.fetchBody(url, "text/html");

        if (html == null) {
            throw new IOException("The notice page answered HTTP 404 for " + usnId);
        }

        logger.debug("Fetched the notice page for {}", usnId);
        return Jsoup.parse(html, url);
    }
}
