package com.github.oogasawa.utility.security.usn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the priority that Ubuntu assigns to a CVE from the page of that CVE.
 *
 * <p>
 * The priority is shown on the page as a small icon, and the name of the icon file carries the
 * value: {@code CVE-Priority-icon-Medium.svg}. This class requests the page and reads that name.
 * </p>
 *
 * <h2>Why the page and not the JSON endpoint</h2>
 *
 * <p>
 * The Ubuntu Security API offers the same value as the {@code priority} field of
 * {@code /security/cves/<CVE id>.json}, and reading a named field is the more direct way to get it.
 * That endpoint, however, answers HTTP 503 and HTTP 504 for long stretches. On 2026-09-01 it failed
 * ten attempts in a row for {@code CVE-2026-66484} while the page of the very same CVE answered
 * HTTP 200 at once. A report that cannot be produced is worth less than one built from a page, so
 * the page is what this class reads.
 * </p>
 *
 * <p>
 * The returned value is one of {@code Low}, {@code Medium}, {@code High}, {@code Critical} or
 * {@link #UNKNOWN_PRIORITY}. Ubuntu also assigns {@code negligible} and leaves some CVEs unrated,
 * and both are reported as {@link #UNKNOWN_PRIORITY}, which is what this class has always done.
 * </p>
 */
public class UbuntuPriorityFetcher {

    private static final Logger logger = LoggerFactory.getLogger(UbuntuPriorityFetcher.class);

    /** Value returned when the priority cannot be determined. */
    public static final String UNKNOWN_PRIORITY = "Unknown";

    private static final String CVE_URL_PREFIX = "https://ubuntu.com/security/";

    /** The name of the icon file carries the priority. */
    private static final Pattern PRIORITY_ICON =
            Pattern.compile("CVE-Priority-icon-([A-Za-z]+)\\.svg", Pattern.CASE_INSENSITIVE);

    /**
     * Requests the page of the given CVE and reads the priority Ubuntu assigned to it.
     *
     * @param cveId the CVE identifier, for example {@code CVE-2024-12345}
     * @return {@code Low}, {@code Medium}, {@code High}, {@code Critical} or
     *         {@link #UNKNOWN_PRIORITY}
     * @throws IOException if the page cannot be obtained after all retries
     * @throws IllegalArgumentException if the identifier is null or blank
     */
    public static String fetchUbuntuPriority(String cveId) throws IOException {

        if (cveId == null || cveId.isBlank()) {
            throw new IllegalArgumentException("CVE ID must not be null or blank");
        }

        String url = CVE_URL_PREFIX + cveId.trim();
        PriorityScanner scanner = new PriorityScanner();

        if (!UbuntuSecurityHttpClient.fetchLines(url, "text/html", scanner)) {
            logger.warn("CVE {} is not present in the Ubuntu security tracker (HTTP 404)", cveId);
            return UNKNOWN_PRIORITY;
        }

        String priority = scanner.priority();
        logger.debug("Ubuntu priority for {} is {}", cveId, priority);
        return priority;
    }


    /**
     * Reads the priority out of a page one line at a time and stops at the first icon it sees.
     *
     * <p>
     * The value sought sits a quarter of the way into a page of about eighty five kilobytes, so
     * reading to the end would spend three quarters of the transfer on bytes that cannot change the
     * answer, and a response that stalls after the value has arrived would be thrown away.
     * </p>
     *
     * <p>
     * The first icon of the page is the one taken. Anchoring the search on the heading that names
     * the priority Ubuntu assigned was tried and abandoned: the pages are not all written to the
     * same pattern, so a rule that depends on a particular heading being present does not hold
     * across them, while the first icon does.
     * </p>
     */
    static class PriorityScanner implements UbuntuSecurityHttpClient.LineScanner {

        private String found = null;

        @Override
        public boolean scan(String line) {
            Matcher matcher = PRIORITY_ICON.matcher(line);
            if (!matcher.find()) {
                return false;
            }
            this.found = normalizePriority(matcher.group(1));
            return true;
        }

        /**
         * Returns the priority found.
         *
         * @return the priority, or {@link #UNKNOWN_PRIORITY} when the page showed none
         */
        String priority() {
            return this.found != null ? this.found : UNKNOWN_PRIORITY;
        }
    }

    /**
     * Reads the priority out of the page of a CVE.
     *
     * <p>
     * The first icon of the page is the one taken.
     * </p>
     *
     * @param html the page of a CVE
     * @return {@code Low}, {@code Medium}, {@code High}, {@code Critical} or
     *         {@link #UNKNOWN_PRIORITY}
     */
    public static String extractPriority(String html) {
        if (html == null) {
            return UNKNOWN_PRIORITY;
        }
        PriorityScanner scanner = new PriorityScanner();
        for (String line : html.split("\\R")) {
            if (scanner.scan(line)) {
                break;
            }
        }
        return scanner.priority();
    }

    /**
     * Maps a priority read from the page to the value used by the report.
     *
     * @param rawPriority the value taken from the name of the icon file
     * @return {@code Low}, {@code Medium}, {@code High}, {@code Critical} or
     *         {@link #UNKNOWN_PRIORITY}
     */
    public static String normalizePriority(String rawPriority) {
        if (rawPriority == null) {
            return UNKNOWN_PRIORITY;
        }
        switch (rawPriority.trim().toLowerCase()) {
            case "low":
                return "Low";
            case "medium":
                return "Medium";
            case "high":
                return "High";
            case "critical":
                return "Critical";
            default:
                return UNKNOWN_PRIORITY;
        }
    }
}
