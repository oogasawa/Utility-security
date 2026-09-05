package com.github.oogasawa.utility.security.usn;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Retrieves Ubuntu Security Notices from the Ubuntu Security API and converts them into
 * {@link USNEntryJson} objects.
 *
 * <p>
 * This class replaces the previous input path, which parsed the plain text of
 * <i>ubuntu-security-announce</i> mailing list digests. Every field that the mail parser extracted
 * with regular expressions is provided as a named field by the API.
 * </p>
 *
 * <p>
 * Two properties of the API shape the retrieval loop. First, the {@code limit} parameter is capped
 * at {@value #PAGE_SIZE}; a larger value is rejected with HTTP 422. Second, no parameter restricts
 * notices to a publication date range, so this class walks the pages in newest-first order and
 * stops once a notice older than the requested start date appears.
 * </p>
 */
public class UsnApiFetcher {

    private static final Logger logger = LoggerFactory.getLogger(UsnApiFetcher.class);

    /** Endpoint that lists security notices. */
    private static final String NOTICES_URL = "https://ubuntu.com/security/notices.json";

    /** Maximum number of notices the API returns per request. A larger value yields HTTP 422. */
    private static final int PAGE_SIZE = 20;

    /** Value of the {@code type} field that identifies an Ubuntu Security Notice. */
    private static final String NOTICE_TYPE_USN = "USN";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Supplies one page of the notices response.
     *
     * <p>
     * The retrieval loop depends on this interface rather than on the HTTP client so that the
     * paging, the date range and the selection by notice type can be verified with a stub that
     * returns fixed responses.
     * </p>
     */
    public interface NoticePageSource {

        /**
         * Returns one page of the notices response as a JSON string.
         *
         * @param releaseCodename the Ubuntu release codename to filter by
         * @param offset the number of notices to skip
         * @return the response body
         * @throws IOException if the page cannot be obtained
         */
        String fetchPage(String releaseCodename, int offset) throws IOException;
    }

    private final NoticePageSource pageSource;

    /** Where the notices already read are kept, or null to use the one of the release. */
    private final NoticeCache noticeCache;

    /**
     * Creates a fetcher that requests pages from the live Ubuntu Security API.
     */
    public UsnApiFetcher() {
        this(UsnApiFetcher::fetchPageFromApi);
    }

    /**
     * Creates a fetcher that obtains pages from the given source.
     *
     * @param pageSource the source of the notice pages
     */
    public UsnApiFetcher(NoticePageSource pageSource) {
        this(pageSource, null);
    }

    /**
     * Creates a fetcher that obtains pages from the given source and keeps what it read in the
     * given store. Tests use this to work in a directory of their own.
     *
     * @param pageSource the source of the notice pages
     * @param noticeCache where to keep the notices read, or null to use the one of the release
     */
    public UsnApiFetcher(NoticePageSource pageSource, NoticeCache noticeCache) {
        if (pageSource == null) {
            throw new IllegalArgumentException("Page source must not be null");
        }
        this.pageSource = pageSource;
        this.noticeCache = noticeCache;
    }

    /**
     * Retrieves every Ubuntu Security Notice published within the given date range for the given
     * Ubuntu release.
     *
     * <p>
     * Notices whose {@code type} field is not {@code USN} are dropped. The endpoint mixes Kernel
     * Live Patch Security Notices (type {@code LSN}) into the same list, and the API offers no
     * parameter to exclude them.
     * </p>
     *
     * @param start the first publication date to include, inclusive
     * @param end the last publication date to include, inclusive
     * @param releaseCodename the Ubuntu release codename, for example {@code noble} for 24.04 LTS
     * @return the matching notices, newest first
     * @throws IOException if a page cannot be obtained
     * @throws IllegalArgumentException if the arguments are null or the range is inverted
     */
    public List<USNEntryJson> fetchNotices(LocalDate start, LocalDate end, String releaseCodename)
            throws IOException {

        List<JsonNode> notices = fetchRawNotices(start, end, releaseCodename);
        List<USNEntryJson> entries = new ArrayList<USNEntryJson>();
        int skippedNonUsn = 0;

        for (JsonNode notice : notices) {
            if (!NOTICE_TYPE_USN.equals(notice.path("type").asText(""))) {
                skippedNonUsn++;
                continue;
            }
            entries.add(toEntry(notice, publishedDateOf(notice)));
        }

        logger.info("Kept {} Ubuntu Security Notices and skipped {} notices of another type",
                entries.size(), skippedNonUsn);
        return entries;
    }

    /**
     * Retrieves every notice published within the given date range for the given Ubuntu release,
     * whatever its type.
     *
     * <p>
     * The endpoint returns Ubuntu Security Notices and Kernel Live Patch Security Notices in one
     * list. This method leaves both in, so that a caller interested in one or the other selects on
     * the {@code type} field itself.
     * </p>
     *
     * @param start the first publication date to include, inclusive
     * @param end the last publication date to include, inclusive
     * @param releaseCodename the Ubuntu release codename, for example {@code noble} for 24.04 LTS
     * @return the notices, newest first
     * @throws IOException if a page cannot be obtained
     * @throws IllegalArgumentException if the arguments are null or the range is inverted
     */
    public List<JsonNode> fetchRawNotices(LocalDate start, LocalDate end, String releaseCodename)
            throws IOException {

        if (start == null || end == null) {
            throw new IllegalArgumentException("Start and end dates must not be null");
        }
        if (end.isBefore(start)) {
            throw new IllegalArgumentException("End date must not be before start date");
        }
        if (releaseCodename == null || releaseCodename.isBlank()) {
            throw new IllegalArgumentException("Release codename must not be null or blank");
        }

        NoticeCache cache = this.noticeCache != null ? this.noticeCache
                : new NoticeCache(releaseCodename);

        // The stored notices reach back to this date, and every notice published after it is
        // stored, because the store is only ever extended by reading pages from the newest
        // backwards. When that date is at or before the start of the period, the pages older than
        // the newest unstored one hold nothing this run has not already got.
        LocalDate storedBackTo = cache.earliestPublished();
        boolean storedReachesStart = storedBackTo != null && !storedBackTo.isAfter(start);

        int offset = 0;
        int read = 0;
        boolean reachedStart = false;

        while (!reachedStart) {
            logger.info("Requesting notices {} to {} for release {}",
                    offset + 1, offset + PAGE_SIZE, releaseCodename);
            JsonNode notices = MAPPER.readTree(this.pageSource.fetchPage(releaseCodename, offset))
                    .path("notices");

            if (!notices.isArray() || notices.isEmpty()) {
                break;
            }

            boolean everyNoticeWasStored = true;
            for (JsonNode notice : notices) {
                LocalDate published = publishedDateOf(notice);
                if (published == null) {
                    logger.warn("Skipping a notice without a parsable publication date: {}",
                            notice.path("id").asText(""));
                    continue;
                }
                if (!cache.holds(notice.path("id").asText(""))) {
                    everyNoticeWasStored = false;
                }
                cache.put(notice);
                read++;
                if (published.isBefore(start)) {
                    reachedStart = true;
                }
            }

            if (notices.size() < PAGE_SIZE) {
                break;
            }
            if (everyNoticeWasStored && storedReachesStart) {
                logger.info("Every notice of this page was already stored and the stored notices "
                        + "reach back to {}, so the older pages are not requested", storedBackTo);
                break;
            }
            offset += PAGE_SIZE;
        }

        cache.save();
        List<JsonNode> collected = cache.between(start, end);
        logger.info("Fetched {} notices for release {} between {} and {}, of which {} were read "
                + "from the server this run", collected.size(), releaseCodename, start, end, read);
        return collected;
    }

    /**
     * Converts one notice of the API response into a {@link USNEntryJson} object.
     *
     * @param notice one element of the {@code notices} array
     * @param published the publication date already parsed from the notice
     * @return the converted entry
     */
    static USNEntryJson toEntry(JsonNode notice, LocalDate published) {
        USNEntryJson entry = new USNEntryJson();

        entry.id = emptyToNull(notice.path("id").asText(""));
        entry.title = emptyToNull(notice.path("title").asText(""));
        entry.published_date = published.toString();
        entry.summary = collapseWhitespace(notice.path("summary").asText(""));
        entry.description = collapseWhitespace(notice.path("description").asText(""));
        entry.update_instructions = notice.path("instructions").asText("");

        for (JsonNode cve : notice.path("cves_ids")) {
            String cveId = cve.asText("");
            if (!cveId.isEmpty() && !entry.cves.contains(cveId)) {
                entry.cves.add(cveId);
            }
        }

        for (JsonNode release : notice.path("releases")) {
            String version = release.path("version").asText("");
            if (!version.isEmpty() && !entry.releases.contains(version)) {
                entry.releases.add(version);
            }
        }

        return entry;
    }

    /**
     * Reads the publication date of a notice.
     *
     * <p>
     * The {@code published} field carries a timestamp such as
     * {@code 2026-08-27T21:41:58.487680}; only the date part is used.
     * </p>
     *
     * @param notice one element of the {@code notices} array
     * @return the publication date, or {@code null} when the field is missing or malformed
     */
    static LocalDate publishedDateOf(JsonNode notice) {
        String published = notice.path("published").asText("");
        if (published.length() < 10) {
            return null;
        }
        try {
            return LocalDate.parse(published.substring(0, 10));
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /**
     * Requests one page of notices from the live Ubuntu Security API.
     *
     * @param releaseCodename the Ubuntu release codename to filter by
     * @param offset the number of notices to skip
     * @return the response body as a JSON string
     * @throws IOException if the request fails after all retries
     */
    private static String fetchPageFromApi(String releaseCodename, int offset) throws IOException {
        String url = NOTICES_URL
                + "?release=" + URLEncoder.encode(releaseCodename, StandardCharsets.UTF_8)
                + "&order=newest"
                + "&limit=" + PAGE_SIZE
                + "&offset=" + offset;

        String body = UbuntuSecurityHttpClient.fetchJson(url);
        if (body == null) {
            throw new IOException("The notices endpoint answered HTTP 404 for " + url);
        }
        return body;
    }

    /**
     * Replaces every run of whitespace with a single space and trims the result.
     *
     * @param text the text to normalize
     * @return the normalized text
     */
    private static String collapseWhitespace(String text) {
        return text.replaceAll("\\s+", " ").trim();
    }

    /**
     * Converts an empty string to {@code null} so that downstream filters can reject entries whose
     * identifier is missing.
     *
     * @param text the text to convert
     * @return the original text, or {@code null} when it is empty
     */
    private static String emptyToNull(String text) {
        return text.isEmpty() ? null : text;
    }
}
