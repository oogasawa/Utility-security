package com.github.oogasawa.utility.security.usn;

import com.fasterxml.jackson.databind.JsonNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reports the Kernel Live Patch Security Notices of a period, one row each.
 *
 * <p>
 * Canonical publishes two kinds of notice. An Ubuntu Security Notice describes a fix delivered as a
 * new package, and the report of those says whether installing it calls for a reboot. A Kernel
 * Live Patch Security Notice describes a fix delivered into the running kernel, which needs no
 * reboot at all. The second kind is what tells an operator that a kernel fix can be applied without
 * stopping the machine, and it is published separately, roughly once every two months, rather than
 * alongside each kernel notice.
 * </p>
 *
 * <h2>What a row says</h2>
 *
 * <pre>
 * id              the LSN number, for example LSN-0121-1
 * published_date  the day it was published
 * summary         the one line summary Canonical writes
 * severity        the highest Ubuntu priority among the CVEs it fixes
 * flavours        the kernel flavours in use for which the live patch was published
 * patch_version   the version of the live patch itself, for example 121.7
 * kernel_version  the version of the kernel it applies to, for example 6.8.0-1
 * cve_count       how many CVEs it fixes
 * </pre>
 *
 * <p>
 * The flavours reported are the ones the machines actually run, the same set the report of Ubuntu
 * Security Notices keeps. A live patch published for a flavour nobody runs cannot be acted on. When
 * none of the flavours in use appears in a notice, the row still carries an empty {@code flavours}
 * cell, because that is the fact an operator has to read: this live patch does not cover us.
 * </p>
 */
public class LivePatchReporter {

    private static final Logger logger = LoggerFactory.getLogger(LivePatchReporter.class);

    /** Value of the {@code type} field that identifies a Kernel Live Patch Security Notice. */
    private static final String NOTICE_TYPE_LSN = "LSN";

    /**
     * Kernel flavours the machines run.
     *
     * <p>
     * {@code linux} is the generic kernel and {@code nvidia} is the kernel built for NVIDIA
     * hardware. These are the two the report of Ubuntu Security Notices keeps, and the two whose
     * live patches can be acted on.
     * </p>
     */
    private static final List<String> FLAVOURS_IN_USE = List.of("linux", "nvidia");

    /** One Kernel Live Patch Security Notice. */
    public record LivePatchEntry(String id, String publishedDate, String summary, String severity,
            String flavours, String patchVersion, String kernelVersion, int cveCount,
            String severeCves) {
    }

    private final UsnApiFetcher noticeFetcher;
    private final USNJsonExporter severityRater;
    private final CvePriorityCache priorityCache;

    /**
     * Creates a reporter that reads from the live Ubuntu Security API and stores CVE priorities in
     * the default file.
     */
    public LivePatchReporter() {
        this(new UsnApiFetcher(), new CvePriorityCache(CvePriorityCache.defaultCacheFile()));
    }

    /**
     * Creates a reporter that reads notices from the given fetcher and CVE priorities through the
     * given cache.
     *
     * @param noticeFetcher the source of the notices
     * @param priorityCache the cache of CVE priorities
     */
    public LivePatchReporter(UsnApiFetcher noticeFetcher, CvePriorityCache priorityCache) {
        this.noticeFetcher = noticeFetcher;
        this.priorityCache = priorityCache;
        this.severityRater = new USNJsonExporter(priorityCache);
    }

    /**
     * Prints the report of the period as a table of tab separated values.
     *
     * @param start the first publication date to include, inclusive
     * @param end the last publication date to include, inclusive
     * @param releaseCodename the Ubuntu release codename, for example {@code noble} for 24.04 LTS
     */
    public void report(LocalDate start, LocalDate end, String releaseCodename) {
        this.priorityCache.load();
        try {
            List<LivePatchEntry> entries = new ArrayList<LivePatchEntry>(
                    collect(start, end, releaseCodename));
            entries.sort(java.util.Comparator
                    .comparing(LivePatchEntry::publishedDate)
                    .thenComparing(LivePatchEntry::id));

            System.out.println(
                    "id\tpublished_date\tsummary\tseverity\tflavours\tpatch_version\t"
                            + "kernel_version\tcve_count\tsevere_cves");
            for (LivePatchEntry entry : entries) {
                System.out.printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s%n",
                        entry.id(), entry.publishedDate(), entry.summary(), entry.severity(),
                        entry.flavours(), entry.patchVersion(), entry.kernelVersion(),
                        entry.cveCount(), entry.severeCves());
            }

        } catch (IOException e) {
            System.err.println("Failed to retrieve the notices: " + e.getMessage());
        } finally {
            this.priorityCache.save();
        }
    }

    /**
     * Builds one entry per Kernel Live Patch Security Notice of the period.
     *
     * @param start the first publication date to include, inclusive
     * @param end the last publication date to include, inclusive
     * @param releaseCodename the Ubuntu release codename
     * @return the entries, in the order the notices were retrieved
     * @throws IOException if the notices cannot be obtained
     */
    List<LivePatchEntry> collect(LocalDate start, LocalDate end, String releaseCodename)
            throws IOException {

        List<LivePatchEntry> entries = new ArrayList<LivePatchEntry>();

        for (JsonNode notice : this.noticeFetcher.fetchRawNotices(start, end, releaseCodename)) {
            if (!NOTICE_TYPE_LSN.equals(notice.path("type").asText(""))) {
                continue;
            }
            entries.add(toEntry(notice, releaseCodename));
        }

        logger.info("Found {} Kernel Live Patch Security Notices for release {} between {} and {}",
                entries.size(), releaseCodename, start, end);
        return entries;
    }

    /**
     * Converts one Kernel Live Patch Security Notice into a row of the report.
     *
     * @param notice the notice
     * @param releaseCodename the Ubuntu release whose packages are read
     * @return the row
     */
    private LivePatchEntry toEntry(JsonNode notice, String releaseCodename) {

        String id = notice.path("id").asText("");
        String publishedDate = notice.path("published").asText("");
        publishedDate = publishedDate.length() >= 10 ? publishedDate.substring(0, 10) : "";

        List<String> cveIds = new ArrayList<String>();
        for (JsonNode cve : notice.path("cves_ids")) {
            cveIds.add(cve.asText(""));
        }

        Map<String, String> patchVersions = new LinkedHashMap<String, String>();
        Map<String, String> kernelVersions = new LinkedHashMap<String, String>();
        for (JsonNode pkg : notice.path("release_packages").path(releaseCodename)) {
            String name = pkg.path("name").asText("");
            if (!FLAVOURS_IN_USE.contains(name)) {
                continue;
            }
            if (pkg.path("is_source").asBoolean(false)) {
                kernelVersions.put(name, pkg.path("version").asText(""));
            } else {
                patchVersions.put(name, pkg.path("version").asText(""));
            }
        }

        USNJsonExporter.CveRating rating = this.severityRater.rateCves(cveIds, id);

        return new LivePatchEntry(id, publishedDate,
                collapseWhitespace(notice.path("summary").asText("")),
                rating.severity(),
                String.join(" ", patchVersions.keySet()),
                String.join(" ", patchVersions.values()),
                String.join(" ", kernelVersions.values()),
                cveIds.size(),
                String.join(" ", rating.severeCveIds()));
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
}
