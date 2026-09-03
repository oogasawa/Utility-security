package com.github.oogasawa.utility.security.usn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Unit tests for {@link CvePriorityCache}.
 *
 * <p>
 * These tests touch no external service. Each test writes to a directory that JUnit creates and
 * removes.
 * </p>
 */
@DisplayName("CvePriorityCache — storing the priority of a CVE between runs")
public class CvePriorityCacheTest {

    @TempDir
    Path tempDir;

    private Path cacheFile() {
        return this.tempDir.resolve("cve-priority.tsv");
    }

    @Test
    @DisplayName("A priority stored in one run is read back in the next")
    void get_priorityStoredInAnEarlierRun_returnsIt() {
        CvePriorityCache first = new CvePriorityCache(cacheFile());
        first.load();
        first.put("CVE-2025-4207", "Medium");
        first.save();

        CvePriorityCache second = new CvePriorityCache(cacheFile());
        second.load();

        assertEquals("Medium", second.get("CVE-2025-4207"));
    }

    @Test
    @DisplayName("A CVE that was never stored is reported as absent")
    void get_cveNeverStored_returnsNull() {
        CvePriorityCache cache = new CvePriorityCache(cacheFile());
        cache.load();

        assertNull(cache.get("CVE-2025-0001"));
    }

    @Test
    @DisplayName("A missing file is treated as nothing stored yet")
    void load_missingFile_leavesTheCacheEmpty() {
        CvePriorityCache cache = new CvePriorityCache(this.tempDir.resolve("absent.tsv"));
        cache.load();

        assertEquals(0, cache.size());
    }

    @Test
    @DisplayName("Every priority that the report ranks is stored")
    void put_rankedPriorities_storesAllOfThem() {
        CvePriorityCache cache = new CvePriorityCache(cacheFile());
        cache.put("CVE-2025-0001", "Low");
        cache.put("CVE-2025-0002", "Medium");
        cache.put("CVE-2025-0003", "High");
        cache.put("CVE-2025-0004", "Critical");

        assertEquals(4, cache.size());
    }

    @Test
    @DisplayName("An unranked answer is not stored, so it is asked again next time")
    void put_unrankedPriority_isNotStored() {
        CvePriorityCache cache = new CvePriorityCache(cacheFile());
        cache.put("CVE-2025-0005", "Unknown");
        cache.put("CVE-2025-0006", "negligible");

        assertEquals(0, cache.size());
        assertNull(cache.get("CVE-2025-0005"));
        assertNull(cache.get("CVE-2025-0006"));
    }

    @Test
    @DisplayName("The file holds two tab separated columns sorted by CVE identifier")
    void save_severalPriorities_writesASortedTableOfTwoColumns() throws IOException {
        CvePriorityCache cache = new CvePriorityCache(cacheFile());
        cache.put("CVE-2025-0003", "High");
        cache.put("CVE-2025-0001", "Low");
        cache.put("CVE-2025-0002", "Medium");
        cache.save();

        List<String> lines = Files.readAllLines(cacheFile(), StandardCharsets.UTF_8);

        assertIterableEquals(List.of(
                "CVE-2025-0001\tLow",
                "CVE-2025-0002\tMedium",
                "CVE-2025-0003\tHigh"), lines);
    }

    @Test
    @DisplayName("Nothing is written when no priority was added")
    void save_nothingAdded_writesNoFile() {
        CvePriorityCache cache = new CvePriorityCache(cacheFile());
        cache.load();
        cache.save();

        assertFalse(Files.exists(cacheFile()));
    }

    @Test
    @DisplayName("The directory of the file is created when it does not exist")
    void save_missingDirectory_createsIt() {
        Path nested = this.tempDir.resolve("a").resolve("b").resolve("cve-priority.tsv");
        CvePriorityCache cache = new CvePriorityCache(nested);
        cache.put("CVE-2025-0001", "Low");
        cache.save();

        assertTrue(Files.isRegularFile(nested));
    }

    @Test
    @DisplayName("A malformed line is skipped and the sound lines are kept")
    void load_malformedLine_isSkipped() throws IOException {
        Files.writeString(cacheFile(), String.join("\n",
                "CVE-2025-0001\tLow",
                "this line has no tab",
                "CVE-2025-0002\tNotAPriority",
                "CVE-2025-0003\tHigh",
                ""), StandardCharsets.UTF_8);

        CvePriorityCache cache = new CvePriorityCache(cacheFile());
        cache.load();

        assertEquals(2, cache.size());
        assertIterableEquals(List.of("CVE-2025-0001", "CVE-2025-0003"), cache.storedCveIds());
    }

    // ---------------------------------------------------------------------------------------
    // The file is written as the run goes, so an interrupted run keeps what it obtained
    // ---------------------------------------------------------------------------------------

    @Test
    @DisplayName("A priority is written to the file at once, before the run ends")
    void put_rankedPriority_appendsToTheFileWithoutWaitingForSave() throws IOException {
        CvePriorityCache cache = new CvePriorityCache(cacheFile());
        cache.load();
        cache.put("CVE-2026-0001", "High");

        // save() has deliberately not been called.
        assertIterableEquals(List.of("CVE-2026-0001\tHigh"),
                Files.readAllLines(cacheFile(), StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("A run interrupted after two CVEs leaves both of them readable")
    void load_fileLeftByAnInterruptedRun_readsEveryAppendedLine() {
        CvePriorityCache interrupted = new CvePriorityCache(cacheFile());
        interrupted.load();
        interrupted.put("CVE-2026-0002", "Medium");
        interrupted.put("CVE-2026-0001", "High");
        // The run stops here. save() is never reached.

        CvePriorityCache next = new CvePriorityCache(cacheFile());
        next.load();

        assertEquals(2, next.size());
        assertEquals("Medium", next.get("CVE-2026-0002"));
        assertEquals("High", next.get("CVE-2026-0001"));
    }

    @Test
    @DisplayName("The end of a run rewrites the file sorted and without repetition")
    void save_afterAppends_rewritesTheFileSortedWithoutRepetition() throws IOException {
        Files.writeString(cacheFile(), String.join("\n",
                "CVE-2026-0003\tHigh",
                "CVE-2026-0001\tLow",
                "CVE-2026-0003\tHigh",
                ""), StandardCharsets.UTF_8);

        CvePriorityCache cache = new CvePriorityCache(cacheFile());
        cache.load();
        cache.save();

        assertIterableEquals(List.of(
                "CVE-2026-0001\tLow",
                "CVE-2026-0003\tHigh"),
                Files.readAllLines(cacheFile(), StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("Storing the same priority twice does not repeat the line")
    void put_samePriorityTwice_appendsOnlyOnce() throws IOException {
        CvePriorityCache cache = new CvePriorityCache(cacheFile());
        cache.put("CVE-2026-0001", "High");
        cache.put("CVE-2026-0001", "High");

        assertIterableEquals(List.of("CVE-2026-0001\tHigh"),
                Files.readAllLines(cacheFile(), StandardCharsets.UTF_8));
    }
}
