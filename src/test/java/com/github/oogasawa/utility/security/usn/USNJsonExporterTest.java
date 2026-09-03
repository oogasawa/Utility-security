package com.github.oogasawa.utility.security.usn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Unit tests for the reboot and livepatch judgements of {@link USNJsonExporter}.
 *
 * <p>
 * Both judgements read the update instructions of a notice. The previous version took that text
 * from the body of the USN HTML page, and the Ubuntu Security API returns the same text in its
 * {@code instructions} field. These tests feed the judgements with text of both shapes and touch no
 * external service.
 * </p>
 */
@DisplayName("USNJsonExporter — reboot and livepatch judged from the update instructions")
public class USNJsonExporterTest {

    /**
     * The update instructions of a kernel notice as the Ubuntu Security API returns them, with the
     * line breaks that the field carries.
     */
    private static final String KERNEL_INSTRUCTIONS_FROM_API = """
            After a standard system update you need to reboot your computer to make
            all the necessary changes.

            ATTENTION: Due to an unavoidable ABI change the kernel updates have
            been given a new version number.
            """;

    /** The update instructions of a notice whose package is replaced without a restart. */
    private static final String INSTRUCTIONS_WITHOUT_REBOOT = """
            In general, a standard system update will make all the necessary changes.
            """;

    /** Update instructions that offer the Canonical Livepatch service. */
    private static final String INSTRUCTIONS_WITH_LIVEPATCH = """
            A Canonical Livepatch is available for this issue, so the fix can be
            applied without a restart.
            """;

    private static USNEntryJson entryTitled(String title) {
        USNEntryJson entry = new USNEntryJson();
        entry.id = "USN-0001-1";
        entry.title = title;
        return entry;
    }

    @Test
    @DisplayName("Instructions that ask for a reboot set the reboot column to yes")
    void determineRebootRequirement_instructionsAskForAReboot_setsYes() {
        USNEntryJson entry = entryTitled("Linux kernel vulnerabilities");

        USNJsonExporter.determineRebootRequirement(entry, KERNEL_INSTRUCTIONS_FROM_API);

        assertEquals("yes", entry.needs_reboot);
    }

    @Test
    @DisplayName("The phrase is found even when a line break falls inside it")
    void determineRebootRequirement_phraseBrokenAcrossLines_setsYes() {
        USNEntryJson entry = entryTitled("Linux kernel vulnerabilities");

        USNJsonExporter.determineRebootRequirement(entry,
                "After a standard system update you need to reboot your\ncomputer.");

        assertEquals("yes", entry.needs_reboot);
    }

    @Test
    @DisplayName("The second accepted wording also sets the reboot column to yes")
    void determineRebootRequirement_instructionsStateARebootIsRequired_setsYes() {
        USNEntryJson entry = entryTitled("OpenSSL vulnerabilities");

        USNJsonExporter.determineRebootRequirement(entry,
                "After the package is replaced, a reboot is required.");

        assertEquals("yes", entry.needs_reboot);
    }

    @Test
    @DisplayName("Instructions without a reboot phrase set the reboot column to no")
    void determineRebootRequirement_instructionsWithoutARebootPhrase_setsNo() {
        USNEntryJson entry = entryTitled("Vim vulnerability");

        USNJsonExporter.determineRebootRequirement(entry, INSTRUCTIONS_WITHOUT_REBOOT);

        assertEquals("no", entry.needs_reboot);
    }

    @Test
    @DisplayName("Instructions offering Canonical Livepatch set the livepatch column to yes")
    void determineLivepatchAvailability_instructionsOfferLivepatch_setsYes() {
        USNEntryJson entry = entryTitled("Linux kernel vulnerabilities");

        USNJsonExporter.determineLivepatchAvailability(entry, INSTRUCTIONS_WITH_LIVEPATCH);

        assertEquals("yes", entry.livepatch);
    }

    @Test
    @DisplayName("A kernel notice without the livepatch phrase sets the livepatch column to no")
    void determineLivepatchAvailability_kernelNoticeWithoutThePhrase_setsNo() {
        USNEntryJson entry = entryTitled("Linux kernel vulnerabilities");

        USNJsonExporter.determineLivepatchAvailability(entry, KERNEL_INSTRUCTIONS_FROM_API);

        assertEquals("no", entry.livepatch);
    }

    @Test
    @DisplayName("A notice about another package leaves the livepatch column not applicable")
    void determineLivepatchAvailability_noticeAboutAnotherPackage_setsNotApplicable() {
        USNEntryJson entry = entryTitled("Vim vulnerability");

        USNJsonExporter.determineLivepatchAvailability(entry, INSTRUCTIONS_WITHOUT_REBOOT);

        assertEquals("NA", entry.livepatch);
    }

    @Test
    @DisplayName("Absent update instructions leave the reboot column at no")
    void determineRebootRequirement_nullInstructions_setsNo() {
        USNEntryJson entry = entryTitled("Vim vulnerability");

        USNJsonExporter.determineRebootRequirement(entry, null);

        assertEquals("no", entry.needs_reboot);
    }

    @Test
    @DisplayName("Text taken from the HTML page yields the same judgement as the API field")
    void determineRebootRequirement_textCollapsedByJsoup_setsYes() {
        USNEntryJson entry = entryTitled("Linux kernel vulnerabilities");

        // jsoup collapses the line breaks of the page into single spaces.
        USNJsonExporter.determineRebootRequirement(entry,
                "After a standard system update you need to reboot your computer to make "
                        + "all the necessary changes. ATTENTION: Due to an unavoidable ABI change");

        assertEquals("yes", entry.needs_reboot);
    }

    // ---------------------------------------------------------------------------------------
    // Severity: the three situations that leave a notice without a rank are told apart
    // ---------------------------------------------------------------------------------------

    /** Answers a fixed priority per CVE, and records which CVEs were asked for. */
    static class StubCvePriorityLookup implements USNJsonExporter.CvePriorityLookup {

        private final Map<String, String> priorityByCveId = new HashMap<String, String>();
        private final Set<String> failing = new HashSet<String>();
        final List<String> askedCveIds = new ArrayList<String>();

        StubCvePriorityLookup answering(String cveId, String priority) {
            this.priorityByCveId.put(cveId, priority);
            return this;
        }

        StubCvePriorityLookup failingFor(String cveId) {
            this.failing.add(cveId);
            return this;
        }

        @Override
        public String fetchPriority(String cveId) throws IOException {
            this.askedCveIds.add(cveId);
            if (this.failing.contains(cveId)) {
                throw new IOException("The server did not answer for " + cveId);
            }
            return this.priorityByCveId.getOrDefault(cveId, "Unknown");
        }
    }

    private USNJsonExporter exporterWith(Path cacheFile, StubCvePriorityLookup lookup) {
        return new USNJsonExporter(new CvePriorityCache(cacheFile), lookup);
    }

    /**
     * Builds an entry about a package other than the kernel, so that the severity is decided from
     * the priorities of its CVEs rather than by the rule for kernel notices.
     */
    private static USNEntryJson entryReferring(String... cveIds) {
        USNEntryJson entry = entryTitled("Vim vulnerability");
        entry.cves.addAll(List.of(cveIds));
        return entry;
    }

    @Test
    @DisplayName("A notice that refers to no CVE is reported as NoCve")
    void assignMaxSeverity_noticeWithoutCve_reportsNoCve(@TempDir Path tempDir) {
        USNEntryJson entry = entryTitled("PAM vulnerability");
        StubCvePriorityLookup lookup = new StubCvePriorityLookup();

        exporterWith(tempDir.resolve("c.tsv"), lookup).assignMaxSeverity(entry);

        assertEquals(USNJsonExporter.SEVERITY_NO_CVE, entry.severity);
        assertEquals(0, lookup.askedCveIds.size());
    }

    @Test
    @DisplayName("A CVE whose priority cannot be retrieved is reported as LookupFailed")
    void assignMaxSeverity_priorityCannotBeRetrieved_reportsLookupFailed(@TempDir Path tempDir) {
        USNEntryJson entry = entryReferring("CVE-2026-0001", "CVE-2026-0002");
        StubCvePriorityLookup lookup = new StubCvePriorityLookup()
                .answering("CVE-2026-0001", "Medium")
                .failingFor("CVE-2026-0002");

        exporterWith(tempDir.resolve("c.tsv"), lookup).assignMaxSeverity(entry);

        assertEquals(USNJsonExporter.SEVERITY_LOOKUP_FAILED, entry.severity);
    }

    @Test
    @DisplayName("A notice whose CVEs Ubuntu has none of them ranked is reported as Unrated")
    void assignMaxSeverity_noCveIsRanked_reportsUnrated(@TempDir Path tempDir) {
        USNEntryJson entry = entryReferring("CVE-2026-0003", "CVE-2026-0004");
        StubCvePriorityLookup lookup = new StubCvePriorityLookup()
                .answering("CVE-2026-0003", "negligible")
                .answering("CVE-2026-0004", "Unknown");

        exporterWith(tempDir.resolve("c.tsv"), lookup).assignMaxSeverity(entry);

        assertEquals(USNJsonExporter.SEVERITY_UNRATED, entry.severity);
    }

    @Test
    @DisplayName("An unranked CVE does not hide the rank of the ones Ubuntu has ranked")
    void assignMaxSeverity_someCvesRankedAndSomeNot_reportsTheHighestRanked(
            @TempDir Path tempDir) {
        USNEntryJson entry = entryReferring("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003");
        StubCvePriorityLookup lookup = new StubCvePriorityLookup()
                .answering("CVE-2026-0001", "Medium")
                .answering("CVE-2026-0002", "Critical")
                .answering("CVE-2026-0003", "negligible");

        exporterWith(tempDir.resolve("c.tsv"), lookup).assignMaxSeverity(entry);

        assertEquals("Critical", entry.severity);
        assertIterableEquals(List.of("CVE-2026-0002"), entry.severeCves);
    }

    @Test
    @DisplayName("Every CVE is looked up even after one of them fails, so all reach the cache")
    void assignMaxSeverity_oneCveFails_theOthersAreStillLookedUp(@TempDir Path tempDir) {
        USNEntryJson entry = entryReferring("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003");
        StubCvePriorityLookup lookup = new StubCvePriorityLookup()
                .failingFor("CVE-2026-0001")
                .answering("CVE-2026-0002", "High")
                .answering("CVE-2026-0003", "Medium");

        exporterWith(tempDir.resolve("c.tsv"), lookup).assignMaxSeverity(entry);

        assertEquals(USNJsonExporter.SEVERITY_LOOKUP_FAILED, entry.severity);
        assertEquals(3, lookup.askedCveIds.size());
    }

    @Test
    @DisplayName("A CVE obtained after a failed one still reaches the cache")
    void assignMaxSeverity_oneCveFails_theOthersAreStored(@TempDir Path tempDir) {
        Path cacheFile = tempDir.resolve("c.tsv");
        CvePriorityCache cache = new CvePriorityCache(cacheFile);
        StubCvePriorityLookup lookup = new StubCvePriorityLookup()
                .failingFor("CVE-2026-0001")
                .answering("CVE-2026-0002", "High");

        USNEntryJson entry = entryReferring("CVE-2026-0001", "CVE-2026-0002");
        new USNJsonExporter(cache, lookup).assignMaxSeverity(entry);
        cache.save();

        CvePriorityCache reloaded = new CvePriorityCache(cacheFile);
        reloaded.load();
        assertEquals("High", reloaded.get("CVE-2026-0002"));
    }

    @Test
    @DisplayName("A failed lookup outweighs a rank that was obtained")
    void assignMaxSeverity_oneFailsAndAnotherIsRanked_reportsLookupFailed(
            @TempDir Path tempDir) {
        USNEntryJson entry = entryReferring("CVE-2026-0001", "CVE-2026-0002");
        StubCvePriorityLookup lookup = new StubCvePriorityLookup()
                .answering("CVE-2026-0001", "High")
                .failingFor("CVE-2026-0002");

        exporterWith(tempDir.resolve("c.tsv"), lookup).assignMaxSeverity(entry);

        assertEquals(USNJsonExporter.SEVERITY_LOOKUP_FAILED, entry.severity);
    }

    @Test
    @DisplayName("LookupFailed and Unrated and NoCve are three different values")
    void severityValues_threeSituations_areNamedDifferently() {
        assertNotEquals(USNJsonExporter.SEVERITY_LOOKUP_FAILED, USNJsonExporter.SEVERITY_UNRATED);
        assertNotEquals(USNJsonExporter.SEVERITY_LOOKUP_FAILED, USNJsonExporter.SEVERITY_NO_CVE);
        assertNotEquals(USNJsonExporter.SEVERITY_UNRATED, USNJsonExporter.SEVERITY_NO_CVE);
    }

    @Test
    @DisplayName("The highest priority among the CVEs becomes the severity of the notice")
    void assignMaxSeverity_everyCveRanked_reportsTheHighest(@TempDir Path tempDir) {
        USNEntryJson entry = entryReferring("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003");
        StubCvePriorityLookup lookup = new StubCvePriorityLookup()
                .answering("CVE-2026-0001", "Medium")
                .answering("CVE-2026-0002", "High")
                .answering("CVE-2026-0003", "Low");

        exporterWith(tempDir.resolve("c.tsv"), lookup).assignMaxSeverity(entry);

        assertEquals("High", entry.severity);
    }

    // ---------------------------------------------------------------------------------------
    // Severity: a priority already stored is not asked for again
    // ---------------------------------------------------------------------------------------

    @Test
    @DisplayName("A priority held by the cache is used without asking the API")
    void assignMaxSeverity_priorityAlreadyStored_doesNotAskTheApi(@TempDir Path tempDir) {
        Path cacheFile = tempDir.resolve("c.tsv");
        CvePriorityCache cache = new CvePriorityCache(cacheFile);
        cache.put("CVE-2026-0001", "High");
        cache.save();

        USNEntryJson entry = entryReferring("CVE-2026-0001");
        StubCvePriorityLookup lookup = new StubCvePriorityLookup();

        USNJsonExporter exporter = new USNJsonExporter(new CvePriorityCache(cacheFile), lookup);
        exporter.loadPriorityCache();
        exporter.assignMaxSeverity(entry);

        assertEquals("High", entry.severity);
        assertEquals(0, lookup.askedCveIds.size());
    }

    @Test
    @DisplayName("A priority obtained from the API is stored for the next run")
    void assignMaxSeverity_priorityObtainedFromTheApi_isStored(@TempDir Path tempDir) {
        Path cacheFile = tempDir.resolve("c.tsv");
        CvePriorityCache cache = new CvePriorityCache(cacheFile);
        StubCvePriorityLookup lookup = new StubCvePriorityLookup()
                .answering("CVE-2026-0001", "Critical");

        USNJsonExporter exporter = new USNJsonExporter(cache, lookup);
        exporter.assignMaxSeverity(entryReferring("CVE-2026-0001"));
        cache.save();

        CvePriorityCache reloaded = new CvePriorityCache(cacheFile);
        reloaded.load();
        assertEquals("Critical", reloaded.get("CVE-2026-0001"));
    }

    // ---------------------------------------------------------------------------------------
    // Kernel notices, and the merging of the issues that share a USN number
    // ---------------------------------------------------------------------------------------

    private static USNEntryJson issue(String id, String title, String published, String... cveIds) {
        USNEntryJson entry = new USNEntryJson();
        entry.id = id;
        entry.title = title;
        entry.published_date = published;
        entry.cves.addAll(List.of(cveIds));
        entry.releases.add("24.04");
        return entry;
    }

    @Test
    @DisplayName("A kernel notice is rated from its CVEs like any other notice")
    void assignMaxSeverity_kernelNotice_isRatedFromItsCves(@TempDir Path tempDir) {
        USNEntryJson entry = entryReferring("CVE-2026-0001", "CVE-2026-0002");
        entry.title = "Linux kernel vulnerabilities";
        StubCvePriorityLookup lookup = new StubCvePriorityLookup()
                .answering("CVE-2026-0001", "Medium")
                .answering("CVE-2026-0002", "High");

        exporterWith(tempDir.resolve("c.tsv"), lookup).assignMaxSeverity(entry);

        assertEquals("High", entry.severity);
        assertEquals(2, lookup.askedCveIds.size());
    }

    @Test
    @DisplayName("A notice about another package is rated from its CVEs")
    void assignMaxSeverity_noticeAboutAnotherPackage_isRatedFromItsCves(@TempDir Path tempDir) {
        USNEntryJson entry = entryReferring("CVE-2026-0001");
        entry.title = "Vim vulnerability";
        StubCvePriorityLookup lookup = new StubCvePriorityLookup()
                .answering("CVE-2026-0001", "High");

        exporterWith(tempDir.resolve("c.tsv"), lookup).assignMaxSeverity(entry);

        assertEquals("High", entry.severity);
        assertEquals(1, lookup.askedCveIds.size());
    }

    @Test
    @DisplayName("The suffix that marks a re-issue is dropped from the USN number")
    void baseNoticeId_identifierWithSuffix_returnsTheNumber() {
        assertEquals("USN-8643", USNJsonExporter.baseNoticeId("USN-8643-5"));
        assertEquals("USN-8643", USNJsonExporter.baseNoticeId("USN-8643"));
        assertEquals("LSN-0121", USNJsonExporter.baseNoticeId("LSN-0121-1"));
    }

    @Test
    @DisplayName("The issues of one USN number become one entry")
    void collapseReissues_severalIssuesOfOneNumber_becomeOneEntry() {
        List<USNEntryJson> collapsed = USNJsonExporter.collapseReissues(List.of(
                issue("USN-8643-5", "Linux kernel vulnerabilities", "2026-08-27", "CVE-A"),
                issue("USN-8643-1", "Linux kernel vulnerabilities", "2026-08-18", "CVE-A"),
                issue("USN-8700-1", "Vim vulnerability", "2026-08-30", "CVE-B")));

        assertEquals(2, collapsed.size());
        assertEquals("USN-8643-1", collapsed.get(0).id);
        assertIterableEquals(List.of("USN-8643-5"), collapsed.get(0).mergedNoticeIds);
        assertEquals("USN-8700-1", collapsed.get(1).id);
    }

    @Test
    @DisplayName("The CVEs of every merged issue are kept, so the severity does not change")
    void collapseReissues_issuesWithDifferentCves_keepsThemAll() {
        List<USNEntryJson> collapsed = USNJsonExporter.collapseReissues(List.of(
                issue("USN-8492-1", "Linux kernel vulnerabilities", "2026-07-01", "CVE-A"),
                issue("USN-8492-5", "Linux kernel vulnerabilities", "2026-07-10", "CVE-B")));

        assertEquals(1, collapsed.size());
        assertIterableEquals(List.of("CVE-A", "CVE-B"), collapsed.get(0).cves);
    }

    @Test
    @DisplayName("A title naming a kernel flavour does not represent the number")
    void collapseReissues_issueNamingAFlavour_doesNotRepresentTheNumber() {
        List<USNEntryJson> collapsed = USNJsonExporter.collapseReissues(List.of(
                issue("USN-8574-1", "Linux kernel (GCP FIPS) vulnerabilities", "2026-07-21",
                        "CVE-A"),
                issue("USN-8574-2", "Linux kernel vulnerabilities", "2026-07-23", "CVE-A"),
                issue("USN-8574-3", "Linux kernel vulnerabilities", "2026-07-28", "CVE-A")));

        assertEquals(1, collapsed.size());
        assertEquals("USN-8574-2", collapsed.get(0).id);
        assertEquals("Linux kernel vulnerabilities", collapsed.get(0).title);
    }

    @Test
    @DisplayName("A number issued only once is left as it is")
    void collapseReissues_numberIssuedOnce_isLeftAsItIs() {
        List<USNEntryJson> collapsed = USNJsonExporter.collapseReissues(List.of(
                issue("USN-8700-1", "Vim vulnerability", "2026-08-30", "CVE-B")));

        assertEquals(1, collapsed.size());
        assertEquals("USN-8700-1", collapsed.get(0).id);
        assertEquals(0, collapsed.get(0).mergedNoticeIds.size());
    }

    // ---------------------------------------------------------------------------------------
    // Which kernel flavours belong in the report
    // ---------------------------------------------------------------------------------------

    private static boolean isReported(String title, @TempDir Path tempDir) {
        USNEntryJson entry = entryTitled(title);
        entry.published_date = "2026-08-27";
        USNJsonExporter exporter =
                new USNJsonExporter(new CvePriorityCache(tempDir.resolve("c.tsv")),
                        new StubCvePriorityLookup());
        return exporter.reportsNotice(entry);
    }

    @Test
    @DisplayName("The generic kernel is reported")
    void coversAKernelInUse_genericKernel_isReported(@TempDir Path tempDir) {
        assertTrue(isReported("Linux kernel vulnerabilities", tempDir));
        assertTrue(isReported("Linux kernel vulnerability", tempDir));
    }

    @Test
    @DisplayName("The NVIDIA kernel is reported")
    void coversAKernelInUse_nvidiaKernel_isReported(@TempDir Path tempDir) {
        assertTrue(isReported("Linux kernel (NVIDIA) vulnerabilities", tempDir));
    }

    @Test
    @DisplayName("A flavour whose name merely contains NVIDIA is left out")
    void coversAKernelInUse_flavourNamedAfterNvidiaButNotIt_isLeftOut(@TempDir Path tempDir) {
        assertFalse(isReported("Linux kernel (NVIDIA Tegra) vulnerabilities", tempDir));
        assertFalse(isReported("Linux kernel (Low Latency NVIDIA) vulnerabilities", tempDir));
    }

    @Test
    @DisplayName("The flavour is read from the parentheses of the title")
    void kernelFlavourOf_title_returnsTheFlavour() {
        assertEquals("NVIDIA",
                USNJsonExporter.kernelFlavourOf("Linux kernel (NVIDIA) vulnerabilities"));
        assertEquals("NVIDIA Tegra",
                USNJsonExporter.kernelFlavourOf("Linux kernel (NVIDIA Tegra) vulnerabilities"));
        assertEquals("", USNJsonExporter.kernelFlavourOf("Linux kernel vulnerabilities"));
    }

    @Test
    @DisplayName("A flavour that is not installed anywhere is left out")
    void coversAKernelInUse_flavourNotInUse_isLeftOut(@TempDir Path tempDir) {
        assertFalse(isReported("Linux kernel (AWS) vulnerabilities", tempDir));
        assertFalse(isReported("Linux kernel (Azure) vulnerabilities", tempDir));
        assertFalse(isReported("Linux kernel (Oracle) vulnerabilities", tempDir));
        assertFalse(isReported("Linux kernel (FIPS) vulnerabilities", tempDir));
        assertFalse(isReported("Linux kernel (HWE) vulnerabilities", tempDir));
        assertFalse(isReported("Linux kernel (Xilinx) vulnerabilities", tempDir));
        assertFalse(isReported("Linux kernel (GCP) vulnerabilities", tempDir));
        assertFalse(isReported("Linux kernel (Low Latency) vulnerabilities", tempDir));
        assertFalse(isReported("Linux kernel (Raspberry Pi) vulnerabilities", tempDir));
    }

    @Test
    @DisplayName("A notice about anything other than the kernel is always reported")
    void coversAKernelInUse_noticeAboutAnotherPackage_isAlwaysReported(@TempDir Path tempDir) {
        assertTrue(isReported("Vim vulnerability", tempDir));
        assertTrue(isReported("OpenSSL vulnerabilities", tempDir));
    }

    @Test
    @DisplayName("The report is ordered by publication date, oldest first")
    void sortByPublicationDate_entries_putsTheOldestFirst() {
        USNEntryJson newer = entryTitled("Vim vulnerability");
        newer.id = "USN-8700-1";
        newer.published_date = "2026-08-30";
        USNEntryJson older = entryTitled("Perl vulnerabilities");
        older.id = "USN-8100-1";
        older.published_date = "2026-04-02";

        List<USNEntryJson> ordered = USNJsonExporter.sortByPublicationDate(List.of(newer, older));

        assertIterableEquals(List.of("USN-8100-1", "USN-8700-1"),
                ordered.stream().map(entry -> entry.id).toList());
    }

    @Test
    @DisplayName("Notices published on the same day are ordered by their identifier")
    void sortByPublicationDate_sameDay_ordersByIdentifier() {
        USNEntryJson second = entryTitled("Vim vulnerability");
        second.id = "USN-8702-1";
        second.published_date = "2026-08-30";
        USNEntryJson first = entryTitled("Perl vulnerabilities");
        first.id = "USN-8701-1";
        first.published_date = "2026-08-30";

        List<USNEntryJson> ordered = USNJsonExporter.sortByPublicationDate(List.of(second, first));

        assertIterableEquals(List.of("USN-8701-1", "USN-8702-1"),
                ordered.stream().map(entry -> entry.id).toList());
    }
}
