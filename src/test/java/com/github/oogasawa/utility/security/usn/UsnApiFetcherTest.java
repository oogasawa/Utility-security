package com.github.oogasawa.utility.security.usn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit tests for {@link UsnApiFetcher}.
 *
 * <p>
 * These tests touch no external service. A stub implementation of
 * {@link UsnApiFetcher.NoticePageSource} returns fixed pages of the shape that
 * {@code /security/notices.json} returns, so the paging, the date range and the selection by
 * notice type are verified without issuing a request.
 * </p>
 */
@DisplayName("UsnApiFetcher — selection of notices and conversion of their fields")
public class UsnApiFetcherTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Returns fixed pages by offset and records which offsets were requested.
     */
    static class StubNoticePageSource implements UsnApiFetcher.NoticePageSource {

        private final Map<Integer, String> pagesByOffset = new HashMap<Integer, String>();
        final List<Integer> requestedOffsets = new ArrayList<Integer>();

        StubNoticePageSource put(int offset, String page) {
            this.pagesByOffset.put(Integer.valueOf(offset), page);
            return this;
        }

        @Override
        public String fetchPage(String releaseCodename, int offset) throws IOException {
            this.requestedOffsets.add(Integer.valueOf(offset));
            String page = this.pagesByOffset.get(Integer.valueOf(offset));
            if (page == null) {
                throw new IOException("The stub holds no page for offset " + offset);
            }
            return page;
        }
    }

    /** Wraps notice objects in the envelope that the endpoint returns. */
    private static String pageOf(String... notices) {
        return "{\"notices\": [" + String.join(",", notices) + "]}";
    }

    /** Builds one notice of the given identifier, type and publication date. */
    private static String notice(String id, String type, String publishedDate) {
        return """
                {
                  "id": "%s",
                  "type": "%s",
                  "title": "Linux kernel vulnerabilities",
                  "summary": "Several security issues were fixed in the Linux kernel.\\n",
                  "instructions": "After a standard system update you need to reboot your\\ncomputer.\\n",
                  "published": "%sT12:00:00.000000",
                  "cves_ids": ["CVE-2026-00001"],
                  "releases": [{"codename": "noble", "version": "24.04", "support_tag": "LTS"}]
                }
                """.formatted(id, type, publishedDate);
    }

    @Test
    @DisplayName("A notice published before the start date ends the retrieval and is excluded")
    void fetchNotices_noticePublishedBeforeStart_endsRetrievalAndIsExcluded() throws Exception {
        StubNoticePageSource source = new StubNoticePageSource().put(0, pageOf(
                notice("USN-0002-1", "USN", "2026-08-26"),
                notice("USN-0001-1", "USN", "2026-08-20")));

        List<USNEntryJson> entries = new UsnApiFetcher(source)
                .fetchNotices(LocalDate.parse("2026-08-24"), LocalDate.parse("2026-08-31"), "noble");

        assertEquals(1, entries.size());
        assertEquals("USN-0002-1", entries.get(0).id);
    }

    @Test
    @DisplayName("A notice published after the end date is excluded without ending the retrieval")
    void fetchNotices_noticePublishedAfterEnd_isExcluded() throws Exception {
        StubNoticePageSource source = new StubNoticePageSource().put(0, pageOf(
                notice("USN-0003-1", "USN", "2026-09-05"),
                notice("USN-0002-1", "USN", "2026-08-26")));

        List<USNEntryJson> entries = new UsnApiFetcher(source)
                .fetchNotices(LocalDate.parse("2026-08-24"), LocalDate.parse("2026-08-31"), "noble");

        assertEquals(1, entries.size());
        assertEquals("USN-0002-1", entries.get(0).id);
    }

    @Test
    @DisplayName("A Kernel Live Patch Security Notice is excluded")
    void fetchNotices_kernelLivePatchSecurityNotice_isExcluded() throws Exception {
        StubNoticePageSource source = new StubNoticePageSource().put(0, pageOf(
                notice("LSN-0121-1", "LSN", "2026-08-26"),
                notice("USN-0002-1", "USN", "2026-08-26")));

        List<USNEntryJson> entries = new UsnApiFetcher(source)
                .fetchNotices(LocalDate.parse("2026-08-24"), LocalDate.parse("2026-08-31"), "noble");

        assertEquals(1, entries.size());
        assertEquals("USN-0002-1", entries.get(0).id);
    }

    @Test
    @DisplayName("A full page is followed by a request for the next page")
    void fetchNotices_fullPage_requestsTheNextPage() throws Exception {
        String[] firstPage = new String[20];
        for (int i = 0; i < firstPage.length; i++) {
            firstPage[i] = notice(String.format("USN-01%02d-1", i), "USN", "2026-08-26");
        }

        StubNoticePageSource source = new StubNoticePageSource()
                .put(0, pageOf(firstPage))
                .put(20, pageOf(notice("USN-0200-1", "USN", "2026-08-25")));

        List<USNEntryJson> entries = new UsnApiFetcher(source)
                .fetchNotices(LocalDate.parse("2026-08-24"), LocalDate.parse("2026-08-31"), "noble");

        assertEquals(21, entries.size());
        assertIterableEquals(List.of(Integer.valueOf(0), Integer.valueOf(20)),
                source.requestedOffsets);
    }

    @Test
    @DisplayName("An empty page ends the retrieval")
    void fetchNotices_emptyPage_endsRetrieval() throws Exception {
        StubNoticePageSource source = new StubNoticePageSource().put(0, "{\"notices\": []}");

        List<USNEntryJson> entries = new UsnApiFetcher(source)
                .fetchNotices(LocalDate.parse("2026-08-24"), LocalDate.parse("2026-08-31"), "noble");

        assertEquals(0, entries.size());
    }

    @Test
    @DisplayName("An end date before the start date is rejected")
    void fetchNotices_endBeforeStart_throwsIllegalArgumentException() {
        StubNoticePageSource source = new StubNoticePageSource();

        assertThrows(IllegalArgumentException.class,
                () -> new UsnApiFetcher(source).fetchNotices(
                        LocalDate.parse("2026-08-31"), LocalDate.parse("2026-08-24"), "noble"));
    }

    @Test
    @DisplayName("Every field that the report prints is taken from the notice")
    void toEntry_notice_mapsEveryFieldUsedByTheReport() throws Exception {
        JsonNode node = MAPPER.readTree(notice("USN-0002-1", "USN", "2026-08-26"));

        USNEntryJson entry = UsnApiFetcher.toEntry(node, LocalDate.parse("2026-08-26"));

        assertEquals("USN-0002-1", entry.id);
        assertEquals("Linux kernel vulnerabilities", entry.title);
        assertEquals("2026-08-26", entry.published_date);
        assertEquals("Several security issues were fixed in the Linux kernel.", entry.summary);
        assertIterableEquals(List.of("CVE-2026-00001"), entry.cves);
        assertIterableEquals(List.of("24.04"), entry.releases);
    }

    @Test
    @DisplayName("The update instructions are kept so that reboot and livepatch can be judged")
    void toEntry_notice_keepsTheUpdateInstructions() throws Exception {
        JsonNode node = MAPPER.readTree(notice("USN-0002-1", "USN", "2026-08-26"));

        USNEntryJson entry = UsnApiFetcher.toEntry(node, LocalDate.parse("2026-08-26"));

        assertEquals("After a standard system update you need to reboot your\ncomputer.\n",
                entry.update_instructions);
    }

    @Test
    @DisplayName("The date part of the publication timestamp is used")
    void publishedDateOf_timestamp_returnsItsDatePart() throws Exception {
        JsonNode node = MAPPER.readTree("{\"published\": \"2026-08-27T21:41:58.487680\"}");

        assertEquals(LocalDate.parse("2026-08-27"), UsnApiFetcher.publishedDateOf(node));
    }

    @Test
    @DisplayName("A missing publication timestamp yields no date")
    void publishedDateOf_missingField_returnsNull() throws Exception {
        JsonNode node = MAPPER.readTree("{\"id\": \"USN-0002-1\"}");

        assertNull(UsnApiFetcher.publishedDateOf(node));
    }

    @Test
    @DisplayName("A malformed publication timestamp yields no date")
    void publishedDateOf_malformedTimestamp_returnsNull() throws Exception {
        JsonNode node = MAPPER.readTree("{\"published\": \"27 August 2026\"}");

        assertNull(UsnApiFetcher.publishedDateOf(node));
    }
}
