package com.github.oogasawa.utility.security.usn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;

/**
 * Unit tests for {@link NoticeCache}.
 *
 * <p>
 * These tests touch no external service. Each test works in a directory that JUnit creates and
 * removes, so the store of the person running them is neither read nor written.
 * </p>
 */
@DisplayName("NoticeCache — the notices already read from the Ubuntu Security API")
public class NoticeCacheTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path tempDir;

    private static JsonNode notice(String id, String published) {
        try {
            return MAPPER.readTree(String.format(
                    "{\"id\": \"%s\", \"published\": \"%sT00:00:00\", \"type\": \"USN\"}",
                    id, published));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private NoticeCache cache() {
        return new NoticeCache(this.tempDir.resolve("notices.jsonl"));
    }

    @Test
    @DisplayName("A notice that was never added is not held")
    void holds_noticeNeverAdded_isFalse() {
        assertFalse(cache().holds("USN-0001-1"));
    }

    @Test
    @DisplayName("A notice is written as soon as it is added, not at the end of the run")
    void put_notice_isWrittenAtOnce() throws IOException {
        cache().put(notice("USN-0001-1", "2026-08-25"));

        List<String> lines =
                Files.readAllLines(this.tempDir.resolve("notices.jsonl"), StandardCharsets.UTF_8);
        assertEquals(1, lines.size());
        assertTrue(lines.get(0).contains("USN-0001-1"));
    }

    @Test
    @DisplayName("A later run reads what an earlier one stored")
    void load_storedNotice_isReadByALaterCache() {
        cache().put(notice("USN-0001-1", "2026-08-25"));

        assertTrue(cache().holds("USN-0001-1"));
    }

    @Test
    @DisplayName("Adding the same notice twice leaves one notice")
    void put_sameNoticeTwice_leavesOne() {
        NoticeCache cache = cache();
        cache.put(notice("USN-0001-1", "2026-08-25"));
        cache.put(notice("USN-0001-1", "2026-08-25"));

        assertEquals(1, cache.size());
    }

    @Test
    @DisplayName("The earliest publication date is that of the oldest notice stored")
    void earliestPublished_severalNotices_isTheOldest() {
        NoticeCache cache = cache();
        cache.put(notice("USN-0001-1", "2026-08-25"));
        cache.put(notice("USN-0002-1", "2026-08-20"));
        cache.put(notice("USN-0003-1", "2026-08-27"));

        assertEquals(LocalDate.parse("2026-08-20"), cache.earliestPublished());
    }

    @Test
    @DisplayName("An empty store has no earliest publication date")
    void earliestPublished_nothingStored_isNull() {
        assertNull(cache().earliestPublished());
    }

    @Test
    @DisplayName("The notices of a period are returned newest first")
    void between_severalNotices_returnsThoseInThePeriodNewestFirst() {
        NoticeCache cache = cache();
        cache.put(notice("USN-0001-1", "2026-08-25"));
        cache.put(notice("USN-0002-1", "2026-08-20"));
        cache.put(notice("USN-0003-1", "2026-08-27"));

        List<JsonNode> found =
                cache.between(LocalDate.parse("2026-08-21"), LocalDate.parse("2026-08-26"));

        assertIterableEquals(List.of("USN-0001-1"), found.stream()
                .map(n -> n.path("id").asText()).toList());
    }

    @Test
    @DisplayName("A line that is not a notice is skipped rather than stopping the run")
    void load_malformedLine_isSkipped() throws IOException {
        Path file = this.tempDir.resolve("notices.jsonl");
        Files.writeString(file, "not json\n{\"id\": \"USN-0001-1\", \"published\": "
                + "\"2026-08-25T00:00:00\"}\n", StandardCharsets.UTF_8);

        NoticeCache cache = new NoticeCache(file);

        assertEquals(1, cache.size());
        assertTrue(cache.holds("USN-0001-1"));
    }

    @Test
    @DisplayName("Rewriting leaves one line for each notice")
    void save_noticeAddedTwice_leavesOneLine() throws IOException {
        Path file = this.tempDir.resolve("notices.jsonl");
        NoticeCache cache = new NoticeCache(file);
        cache.put(notice("USN-0001-1", "2026-08-25"));
        cache.put(notice("USN-0001-1", "2026-08-26"));

        cache.save();

        assertEquals(1, Files.readAllLines(file, StandardCharsets.UTF_8).size());
    }

    @Test
    @DisplayName("Each release keeps its notices in a file of its own")
    void defaultFile_twoReleases_areNotTheSameFile() {
        assertFalse(NoticeCache.defaultFile("noble").equals(NoticeCache.defaultFile("jammy")));
    }
}
