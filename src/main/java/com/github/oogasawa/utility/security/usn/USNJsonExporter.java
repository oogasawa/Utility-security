package com.github.oogasawa.utility.security.usn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.*;
import java.nio.file.*;
import java.time.LocalDate;
import java.util.*;
import java.util.regex.*;
import java.util.stream.Collectors;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 * A utility class that parses Ubuntu Security Notice (USN) text messages and exports filtered and
 * enriched security entries as either JSON or TSV.
 * <p>
 * This class targets entries relevant to Ubuntu 24.04 (LTS) and focuses on generic kernel reports
 * (excluding cloud-specific or OEM variants). It enhances each entry with severity levels and
 * livepatch support details.
 */
public class USNJsonExporter {

    private static final Logger logger = LoggerFactory.getLogger(USNJsonExporter.class);

    /** Severity reported when the notice refers to no CVE at all. */
    public static final String SEVERITY_NO_CVE = "NoCve";

    /** Severity reported when the priority of a CVE could not be retrieved. */
    public static final String SEVERITY_LOOKUP_FAILED = "LookupFailed";

    /**
     * Severity reported when Ubuntu has ranked none of the CVEs of the notice.
     *
     * <p>
     * A notice that refers to both ranked and unranked CVEs is given the highest rank among the
     * ranked ones. Ubuntu has looked at each of its CVEs and has not yet decided on some of them,
     * and a rank it has decided on is a fact worth reporting: a notice known to carry a Critical
     * CVE is Critical whatever the undecided ones turn out to be.
     * </p>
     */
    public static final String SEVERITY_UNRATED = "Unrated";

    /**
     * Why the priority of one CVE could or could not be used.
     *
     * <p>
     * The three outcomes are kept apart because the reader of the report has to act differently on
     * each. A failed retrieval means the report is incomplete and the notice must be looked at by
     * hand; an unranked CVE means Ubuntu itself has not decided yet.
     * </p>
     */
    enum PriorityLookupOutcome {

        /** Ubuntu ranks the CVE, and the rank was obtained. */
        RANKED,

        /** Ubuntu answered, but with a priority the report does not rank. */
        UNRATED,

        /** The priority could not be retrieved. */
        FAILED
    }

    /**
     * The result of looking up the priority of one CVE.
     *
     * @param outcome why the priority could or could not be used
     * @param level the rank, present only when the outcome is {@link PriorityLookupOutcome#RANKED}
     */
    record PriorityLookup(PriorityLookupOutcome outcome, PriorityLevel level) {}

    /**
     * What the CVEs of one notice add up to.
     *
     * <p>
     * The severity alone says how bad the worst CVE is, but not which CVE that is. A reader who has
     * to decide whether to act tonight or at the next maintenance window needs to look the severe
     * ones up, so they are listed as well.
     * </p>
     *
     * @param severity the highest Ubuntu priority, or the reason no priority could be given
     * @param severeCveIds the CVEs whose Ubuntu priority is High or Critical, in the order they
     *        appear in the notice
     */
    record CveRating(String severity, List<String> severeCveIds) {}

    /**
     * Answers the priority that Ubuntu assigns to one CVE.
     *
     * <p>
     * The severity logic depends on this interface rather than on the HTTP client so that the three
     * outcomes above can be verified with a stub that answers without a request.
     * </p>
     */
    public interface CvePriorityLookup {

        /**
         * Returns the priority of the given CVE.
         *
         * @param cveId the CVE identifier
         * @return {@code Low}, {@code Medium}, {@code High}, {@code Critical} or
         *         {@code Unknown}
         * @throws IOException if the priority cannot be obtained
         */
        String fetchPriority(String cveId) throws IOException;
    }

    private final CvePriorityCache priorityCache;
    private final CvePriorityLookup cvePriorityLookup;

    /**
     * Creates an exporter that asks the Ubuntu Security API and stores CVE priorities in the
     * default file.
     */
    public USNJsonExporter() {
        this(new CvePriorityCache(CvePriorityCache.defaultCacheFile()),
                UbuntuPriorityFetcher::fetchUbuntuPriority);
    }

    /**
     * Creates an exporter that asks the Ubuntu Security API and stores CVE priorities in the given
     * cache.
     *
     * @param priorityCache the cache of CVE priorities
     */
    public USNJsonExporter(CvePriorityCache priorityCache) {
        this(priorityCache, UbuntuPriorityFetcher::fetchUbuntuPriority);
    }

    /**
     * Creates an exporter that obtains CVE priorities from the given source.
     *
     * @param priorityCache the cache of CVE priorities
     * @param cvePriorityLookup the source of CVE priorities
     */
    public USNJsonExporter(CvePriorityCache priorityCache, CvePriorityLookup cvePriorityLookup) {
        if (priorityCache == null) {
            throw new IllegalArgumentException("Priority cache must not be null");
        }
        if (cvePriorityLookup == null) {
            throw new IllegalArgumentException("CVE priority lookup must not be null");
        }
        this.priorityCache = priorityCache;
        this.cvePriorityLookup = cvePriorityLookup;
    }

    /**
     * Enumeration representing severity levels for CVEs, in increasing order of seriousness.
     */
    public enum PriorityLevel {
        LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);

        private final int level;

        PriorityLevel(int level) {
            this.level = level;
        }

        /**
         * Returns the numeric severity ordering associated with the priority.
         *
         * @return integer value where higher numbers indicate higher severity
         */
        public int level() {
            return level;
        }

        /**
         * Parses a user-provided string into a {@link PriorityLevel} if possible.
         *
         * @param value textual severity label, e.g. {@code "High"}
         * @return corresponding {@link PriorityLevel}, or {@code null} when the text is unrecognized
         */
        public static PriorityLevel fromString(String value) {
            if (value == null)
                return null;
            switch (value.trim().toLowerCase()) {
                case "low":
                    return LOW;
                case "medium":
                    return MEDIUM;
                case "high":
                    return HIGH;
                case "critical":
                    return CRITICAL;
                default:
                    return null;
            }
        }

        /**
         * Returns the name with only the first letter capitalized for display in TSV output.
         *
         * @return capitalized representation such as {@code "Medium"}
         */
        public String nameCapitalized() {
            return name().charAt(0) + name().substring(1).toLowerCase();
        }
    }

    /**
     * Main entry point to generate a report from a raw USN message file.
     *
     * <p>
     * The input file should consist of multiple Ubuntu Security Notices as published in the
     * <i>ubuntu-security-announce</i> mailing list digest. These digests are typically received via email
     * and can be concatenated manually or automatically before being passed to this method.
     * <p>
     * You can subscribe to or unsubscribe from the <i>ubuntu-security-announce</i> mailing list via:
     * <a href="https://lists.ubuntu.com/mailman/listinfo/ubuntu-security-announce">
     * https://lists.ubuntu.com/mailman/listinfo/ubuntu-security-announce</a>
     *
     * 
     * @param inputPath the file path to the input plain-text USN data
     * @param format    the desired output format ("json" or "tsv")
     */
    public void report(Path inputPath, String format) {
        loadPriorityCache();
        try (BufferedReader reader = Files.newBufferedReader(inputPath)) {
            List<USNEntryJson> entries = parseUSNMessages(reader);
            
            // Log parsing statistics
            logger.info("=== USN PARSING STATISTICS ===");
            logger.info("Total entries parsed: {}", entries.size());
            
            long nullIdCount = entries.stream()
                .filter(entry -> entry.id == null || entry.id.trim().isEmpty())
                .count();
            logger.info("Entries with null/empty ID: {}", nullIdCount);
            
            long validIdCount = entries.size() - nullIdCount;
            logger.info("Entries with valid ID: {}", validIdCount);
            
            // Show valid USN IDs for debugging
            entries.stream()
                .filter(entry -> entry.id != null && !entry.id.trim().isEmpty())
                .limit(5) // Show first 5 for debugging
                .forEach(entry -> logger.info("Valid USN: ID=[{}], Title=[{}]", 
                    entry.id, entry.title != null ? entry.title.substring(0, Math.min(50, entry.title.length())) + "..." : "null"));

            List<USNEntryJson> filtered = collapseReissues(entries.stream()
                .filter(entry -> entry.id != null && !entry.id.trim().isEmpty())
                .filter(this::appliesToUbuntu2404)
                .filter(this::coversAKernelInUse)
                .collect(Collectors.toList()));
                
            long ubuntu2404Count = entries.stream()
                .filter(entry -> entry.id != null && !entry.id.trim().isEmpty())
                .filter(this::appliesToUbuntu2404)
                .count();
            logger.info("Entries applicable to Ubuntu 24.04: {}", ubuntu2404Count);
            logger.info("Final entries after keeping only the kernels in use: {}", filtered.size());
            logger.info("=== END PARSING STATISTICS ===");

            for (USNEntryJson entry : filtered) {
                assignMaxSeverity(entry);
                try {
                    Document doc = LivepatchHtmlFetcher.fetchUsnDocument(entry.id);
                    String updateInstructions = doc.body().text();
                    determineLivepatchAvailability(entry, updateInstructions);
                    determineRebootRequirement(entry, updateInstructions);
                } catch (IOException e) {
                    logger.warn("Failed to fetch USN document for {}: {}", entry.id, e.getMessage());
                    entry.livepatch = "NA";
                    entry.needs_reboot = "NA";
                }
            }

            print(filtered, format);

        } catch (IOException e) {
            System.err.println("Failed to process security report file: " + e.getMessage());
        } finally {
            this.priorityCache.save();
        }
    }


    /**
     * Generates a report from the Ubuntu Security API instead of from a file of mailing list
     * digests.
     *
     * <p>
     * The notices of the requested period are retrieved from the API, the same filters and
     * judgements as the file based path are applied, and the result is printed in the requested
     * format. The update instructions come from the {@code instructions} field of each notice, so
     * no request to the USN HTML page is made.
     * </p>
     *
     * @param start the first publication date to include, inclusive
     * @param end the last publication date to include, inclusive
     * @param releaseCodename the Ubuntu release codename, for example {@code noble} for 24.04 LTS
     * @param format the desired output format ("json" or "tsv")
     */
    public void report(LocalDate start, LocalDate end, String releaseCodename, String format) {
        loadPriorityCache();
        try {
            List<USNEntryJson> entries =
                    new UsnApiFetcher().fetchNotices(start, end, releaseCodename);

            logger.info("Retrieved {} notices from the Ubuntu Security API", entries.size());

            List<USNEntryJson> filtered = collapseReissues(entries.stream()
                    .filter(entry -> entry.id != null && !entry.id.trim().isEmpty())
                    .filter(this::appliesToUbuntu2404)
                    .filter(this::coversAKernelInUse)
                    .collect(Collectors.toList()));

            logger.info("Final entries after keeping only the kernels in use: {}", filtered.size());

            for (USNEntryJson entry : filtered) {
                assignMaxSeverity(entry);
                determineLivepatchAvailability(entry, entry.update_instructions);
                determineRebootRequirement(entry, entry.update_instructions);
            }

            print(filtered, format);

        } catch (IOException e) {
            System.err.println("Failed to retrieve notices from the Ubuntu Security API: "
                    + e.getMessage());
        } finally {
            this.priorityCache.save();
        }
    }


    /**
     * Prints the entries in the requested format.
     *
     * @param entries the entries to print
     * @param format the desired output format ("json" or "tsv")
     * @throws IOException if JSON serialization fails
     */
    private void print(List<USNEntryJson> entries, String format) throws IOException {
        List<USNEntryJson> ordered = sortByPublicationDate(entries);
        if ("tsv".equalsIgnoreCase(format)) {
            printAsTsv(ordered);
        } else {
            printAsJson(ordered);
        }
    }


    /**
     * Orders the entries by publication date, oldest first.
     *
     * <p>
     * The record reads from the top down in the order the notices were published, so a report
     * appended to it has to arrive in the same order. The Ubuntu Security API answers newest first,
     * which is the opposite. Entries published on the same day are ordered by their identifier, so
     * that two runs of the same period produce the same file.
     * </p>
     *
     * @param entries the entries to order
     * @return a new list, oldest first
     */
    static List<USNEntryJson> sortByPublicationDate(List<USNEntryJson> entries) {
        List<USNEntryJson> ordered = new ArrayList<>(entries);
        ordered.sort(Comparator
                .comparing((USNEntryJson entry) -> entry.published_date == null
                        ? "9999-99-99" : entry.published_date)
                .thenComparing(entry -> entry.id == null ? "" : entry.id));
        return ordered;
    }
    


    /**
     * Checks whether a USN entry applies to Ubuntu 24.04 (with or without LTS label).
     *
     * @param entry the USN entry to check
     * @return true if the entry targets Ubuntu 24.04, false otherwise
     */
    private boolean appliesToUbuntu2404(USNEntryJson entry) {
        return entry.releases.stream()
                .anyMatch(rel -> rel.equals("24.04") || rel.equals("24.04 LTS"));
    }



    /**
     * Assigns the highest severity level among the entry's CVEs to the entry itself. If any CVE has
     * an unknown priority, the entry's severity is set to "Unknown".
     *
     * @param entry the USN entry to modify
     */
    /**
     * Tells whether the notice is about the Linux kernel.
     *
     * @param entry the entry to judge
     * @return true when the title names the Linux kernel
     */
    static boolean isKernelNotice(USNEntryJson entry) {
        return entry.title != null && entry.title.contains("Linux kernel");
    }


    /**
     * Returns the USN number of a notice without the suffix that distinguishes a re-issue.
     *
     * @param noticeId an identifier such as {@code USN-8643-5}
     * @return the number such as {@code USN-8643}, or the identifier itself when it has no suffix
     */
    static String baseNoticeId(String noticeId) {
        if (noticeId == null) {
            return "";
        }
        Matcher matcher = Pattern.compile("^([A-Z]+-\\d+)").matcher(noticeId.trim());
        return matcher.find() ? matcher.group(1) : noticeId.trim();
    }


    /**
     * Merges the notices that share a USN number into one entry each.
     *
     * <p>
     * Canonical issues the same fix again for each kernel flavour and for each Ubuntu release it
     * reaches, and gives each issue the same USN number with a different suffix. The record keeps
     * one row per fix, so the entries of one number become one entry here. Of twenty-one numbers
     * that had more than one issue in the five months to September 2026, thirteen had exactly the
     * same set of CVEs in every issue.
     * </p>
     *
     * <p>
     * The entry that represents the number is the one whose title names no kernel flavour, because
     * a title such as {@code Linux kernel (GCP FIPS) vulnerabilities} would otherwise stand for
     * issues that are not about that flavour at all. Among the entries that qualify, the earliest
     * published one is taken, since that is when the fix was announced. The CVEs and the Ubuntu
     * releases of every merged entry are added to it, so that nothing the severity depends on is
     * lost.
     * </p>
     *
     * @param entries the entries to merge, in the order they were retrieved
     * @return one entry per USN number, in the order the numbers first appeared
     */
    static List<USNEntryJson> collapseReissues(List<USNEntryJson> entries) {

        Map<String, List<USNEntryJson>> byNumber = new LinkedHashMap<>();
        for (USNEntryJson entry : entries) {
            byNumber.computeIfAbsent(baseNoticeId(entry.id), key -> new ArrayList<>()).add(entry);
        }

        List<USNEntryJson> merged = new ArrayList<>();
        for (Map.Entry<String, List<USNEntryJson>> group : byNumber.entrySet()) {
            List<USNEntryJson> issues = group.getValue();
            if (issues.size() == 1) {
                merged.add(issues.get(0));
                continue;
            }
            merged.add(mergeIssues(issues));
        }

        logger.info("Merged {} notices into {} by their USN number", entries.size(), merged.size());
        return merged;
    }


    /**
     * Builds one entry out of the several issues of one USN number.
     *
     * @param issues the entries that share a USN number, at least two of them
     * @return the representative entry, carrying the CVEs and releases of them all
     */
    private static USNEntryJson mergeIssues(List<USNEntryJson> issues) {

        USNEntryJson representative = issues.stream()
                .filter(issue -> issue.title != null && !issue.title.contains("("))
                .min(Comparator.comparing(issue -> nullToLast(issue.published_date)))
                .orElseGet(() -> issues.stream()
                        .min(Comparator.comparing(issue -> nullToLast(issue.published_date)))
                        .orElse(issues.get(0)));

        for (USNEntryJson issue : issues) {
            if (issue == representative) {
                continue;
            }
            representative.mergedNoticeIds.add(issue.id);
            for (String cve : issue.cves) {
                if (!representative.cves.contains(cve)) {
                    representative.cves.add(cve);
                }
            }
            for (String release : issue.releases) {
                if (!representative.releases.contains(release)) {
                    representative.releases.add(release);
                }
            }
        }

        logger.info("{} represents {} and now refers to {} CVEs",
                representative.id, representative.mergedNoticeIds, representative.cves.size());
        return representative;
    }


    /**
     * Orders a missing publication date after every present one.
     *
     * @param publishedDate the date in ISO form, which may be null
     * @return the date, or a string that sorts last
     */
    private static String nullToLast(String publishedDate) {
        return publishedDate == null ? "9999-99-99" : publishedDate;
    }


    /**
     * Reads the stored CVE priorities so that a CVE already known is not requested again.
     */
    void loadPriorityCache() {
        this.priorityCache.load();
    }


    void assignMaxSeverity(USNEntryJson entry) {
        logger.info(String.format("%s, %s, %s", entry.id, entry.title, entry.cves));

        CveRating rating = rateCves(entry.cves, entry.id);
        entry.severity = rating.severity();
        entry.severeCves = rating.severeCveIds();
    }


    /**
     * Determines the severity of a notice from the CVEs it refers to.
     *
     * <p>
     * The severity is the highest Ubuntu priority among the CVEs. A CVE whose priority could not be
     * retrieved, and a CVE that Ubuntu has not ranked, each keep the notice from being given a
     * rank, because a CVE whose rank is unknown cannot be assumed to be no worse than the highest
     * rank found so far.
     * </p>
     *
     * <h2>Every CVE is looked up, even after one of them fails</h2>
     *
     * <p>
     * An earlier version stopped at the first CVE it could not rate, since the answer for the
     * notice was already settled at that point. That saved requests in the run at hand and cost
     * far more in the runs after it. A priority obtained once is stored and never requested again,
     * so a CVE that was never reached is a CVE the next run still has to fetch. One kernel notice
     * refers to several hundred CVEs; stopping at the first failure among them left the rest
     * unstored, and the following run stopped at the same place. Sixteen notices in one run left
     * 1074 CVEs unfetched that way.
     * </p>
     *
     * @param cveIds the CVEs the notice refers to
     * @param noticeId the notice, used in the log
     * @return a ranked priority, or {@link #SEVERITY_NO_CVE}, {@link #SEVERITY_LOOKUP_FAILED} or
     *         {@link #SEVERITY_UNRATED}
     */
    CveRating rateCves(List<String> cveIds, String noticeId) {

        if (cveIds.isEmpty()) {
            return new CveRating(SEVERITY_NO_CVE, List.of());
        }

        List<PriorityLevel> levels = new ArrayList<>();
        List<String> severeCveIds = new ArrayList<>();
        List<String> failedCveIds = new ArrayList<>();
        List<String> unratedCveIds = new ArrayList<>();

        for (String cve : cveIds) {
            PriorityLookup lookup = lookupPriority(cve);

            switch (lookup.outcome()) {
                case FAILED:
                    failedCveIds.add(cve);
                    break;
                case UNRATED:
                    unratedCveIds.add(cve);
                    break;
                default:
                    levels.add(lookup.level());
                    if (lookup.level().level() >= PriorityLevel.HIGH.level()) {
                        severeCveIds.add(cve);
                    }
                    break;
            }
        }

        if (!failedCveIds.isEmpty()) {
            logger.warn("Severity of {} is {} because the priority of {} of its {} CVEs could not "
                    + "be retrieved: {}", noticeId, SEVERITY_LOOKUP_FAILED, failedCveIds.size(),
                    cveIds.size(), failedCveIds);
            return new CveRating(SEVERITY_LOOKUP_FAILED, severeCveIds);
        }
        if (levels.isEmpty()) {
            logger.warn("Severity of {} is {} because Ubuntu has ranked none of its {} CVEs: {}",
                    noticeId, SEVERITY_UNRATED, cveIds.size(), unratedCveIds);
            return new CveRating(SEVERITY_UNRATED, severeCveIds);
        }
        if (!unratedCveIds.isEmpty()) {
            logger.info("Ubuntu has not ranked {} of the {} CVEs of {}: {}. The severity is taken "
                    + "from the {} it has ranked.", unratedCveIds.size(), cveIds.size(), noticeId,
                    unratedCveIds, levels.size());
        }

        PriorityLevel max =
                levels.stream().max(Comparator.comparingInt(PriorityLevel::level)).orElseThrow();
        logger.info("Assigned severity '{}' to {} based on {} CVEs, {} of them High or above",
                max.nameCapitalized(), noticeId, levels.size(), severeCveIds.size());
        return new CveRating(max.nameCapitalized(), severeCveIds);
    }


    
    /**
     * Determines whether Canonical Livepatch is available for a given USN entry.
     *
     * <p>
     * The judgement reads the update instructions of the notice. The previous version took that
     * text from the body of the USN HTML page; the Ubuntu Security API returns the same text in the
     * {@code instructions} field. The rule applied to the text is unchanged.
     * </p>
     *
     * @param entry the USN entry to evaluate
     * @param updateInstructions the update instructions of the notice
     */
    static void determineLivepatchAvailability(USNEntryJson entry, String updateInstructions) {
        String text = normalizeForMatching(updateInstructions);
        if (text.contains("canonical livepatch is available")) {
            entry.livepatch = "yes";
        } else if (entry.title != null && entry.title.toLowerCase().contains("linux kernel")) {
            entry.livepatch = "no";
        } else {
            entry.livepatch = "NA";
        }
    }


    /**
     * Determines whether a reboot is required for the security update described in the given USN
     * document.
     * <p>
     * This method scans the text content of the USN HTML page to identify language indicating that
     * a system reboot is necessary after applying the update. It searches for key phrases such as
     * {@code "a reboot is required"} and {@code "you need to reboot your computer"}. The result is
     * stored in the {@code needs_reboot} field of the given entry as either {@code "yes"} or
     * {@code "no"}.
     *
     * @param entry the USN entry to annotate with reboot information
     * @param updateInstructions the update instructions of the notice
     */
    static void determineRebootRequirement(USNEntryJson entry, String updateInstructions) {
        String text = normalizeForMatching(updateInstructions);
        if (text.contains("a reboot is required")
                || text.contains("you need to reboot your computer")) {
            entry.needs_reboot = "yes";
        } else {
            entry.needs_reboot = "no";
        }
    }


    /**
     * Prepares a text for the string matching used by the reboot and livepatch judgements.
     *
     * <p>
     * The text is lowercased, and every run of whitespace is replaced with a single space so that a
     * phrase broken across lines still matches. The body text of the USN HTML page arrives already
     * collapsed because jsoup collapses it; the {@code instructions} field of the Ubuntu Security
     * API keeps its line breaks. Collapsing here makes both sources yield the same judgement.
     * </p>
     *
     * @param text the text to prepare, which may be null
     * @return the prepared text, which is empty when the input is null
     */
    static String normalizeForMatching(String text) {
        if (text == null) {
            return "";
        }
        return text.replaceAll("\\s+", " ").toLowerCase();
    }

    

    /**
     * Kernel flavours, besides the generic one, whose notices belong in the report.
     *
     * <p>
     * Ubuntu builds the kernel in many flavours and issues a separate notice for each. The machines
     * this report is written for run the generic kernel and the NVIDIA one, so a notice about any
     * other flavour describes a fix for a kernel that is not installed anywhere and would only add
     * a row nobody has to act on.
     * </p>
     */
    private static final List<String> REPORTED_KERNEL_FLAVOURS = List.of("NVIDIA");

    /**
     * Determines whether the notice concerns a kernel that is actually in use.
     *
     * <p>
     * A notice about anything other than the kernel is always kept. A kernel notice is kept when
     * its title names no flavour, which is the generic kernel, or when the flavour it names is
     * exactly one of {@link #REPORTED_KERNEL_FLAVOURS}. Ubuntu writes the flavour in parentheses
     * after {@code Linux kernel}, as in {@code Linux kernel (NVIDIA) vulnerabilities}.
     * </p>
     *
     * <p>
     * The flavour has to match in full. {@code NVIDIA Tegra} is a kernel for an embedded system and
     * {@code Low Latency NVIDIA} is the low latency kernel built for NVIDIA hardware; neither is
     * the {@code NVIDIA} kernel, and matching on a part of the name would report both.
     * </p>
     *
     * <p>
     * The rule names the flavours to keep rather than the ones to drop. Naming the ones to drop had
     * let every flavour Canonical added since the list was written pass through: in the five months
     * to September 2026 that was seventeen notices about the Oracle, FIPS, HWE, Xilinx, GCP and Low
     * Latency kernels.
     * </p>
     *
     * @param entry the USN entry to evaluate
     * @return true when the notice belongs in the report
     */
    boolean reportsNotice(USNEntryJson entry) {
        return coversAKernelInUse(entry);
    }


    private boolean coversAKernelInUse(USNEntryJson entry) {
        if (!isKernelNotice(entry)) {
            return true;
        }
        String flavour = kernelFlavourOf(entry.title);
        return flavour.isEmpty() || REPORTED_KERNEL_FLAVOURS.contains(flavour);
    }


    /**
     * Reads the kernel flavour that a title names.
     *
     * @param title the title of a notice, such as {@code Linux kernel (NVIDIA) vulnerabilities}
     * @return the flavour, such as {@code NVIDIA}, or an empty string for the generic kernel
     */
    static String kernelFlavourOf(String title) {
        if (title == null) {
            return "";
        }
        Matcher matcher = Pattern.compile("\\(([^)]*)\\)").matcher(title);
        return matcher.find() ? matcher.group(1).trim() : "";
    }


    /**
     * Determines the priority that Ubuntu assigns to the given CVE.
     *
     * <p>
     * A priority already held by the cache is used without issuing a request. Otherwise the Ubuntu
     * Security API is asked, and a ranked answer is added to the cache.
     * </p>
     *
     * <p>
     * A failed request and an answer that Ubuntu has not ranked are reported as two different
     * outcomes. Reporting both as one value made the reader of the report unable to tell a notice
     * that nobody has rated yet from a notice whose rating this program failed to obtain.
     * </p>
     *
     * @param cveId the CVE identifier, for example {@code CVE-2024-12345}
     * @return the outcome of the lookup, and the rank when there is one
     */
    private PriorityLookup lookupPriority(String cveId) {

        String storedPriority = this.priorityCache.get(cveId);
        if (storedPriority != null) {
            PriorityLevel storedLevel = PriorityLevel.fromString(storedPriority);
            if (storedLevel != null) {
                logger.info(String.format("storedPriority: %s, %s", storedPriority, cveId));
                return new PriorityLookup(PriorityLookupOutcome.RANKED, storedLevel);
            }
        }

        try {
            String rawPriority = this.cvePriorityLookup.fetchPriority(cveId);
            logger.info(String.format("rawPriority: %s, %s", rawPriority, cveId));

            PriorityLevel level = PriorityLevel.fromString(rawPriority);
            if (level == null) {
                logger.warn("Ubuntu has not ranked CVE {}; it answered '{}'", cveId, rawPriority);
                return new PriorityLookup(PriorityLookupOutcome.UNRATED, null);
            }

            this.priorityCache.put(cveId, rawPriority);
            return new PriorityLookup(PriorityLookupOutcome.RANKED, level);

        } catch (IOException e) {
            logger.error("Could not retrieve the priority of CVE {}: {}", cveId, e.getMessage());
            return new PriorityLookup(PriorityLookupOutcome.FAILED, null);

        } catch (Exception e) {
            logger.error("Could not retrieve the priority of CVE {}: {} ({})",
                    cveId, e.getMessage(), e.getClass().getSimpleName());
            return new PriorityLookup(PriorityLookupOutcome.FAILED, null);
        }
    }


    
    /**
     * Finalizes a current USN entry by assigning accumulated details and updates.
     *
     * @param entry   the entry to finalize
     * @param details the accumulated details buffer
     * @param updates the accumulated update instructions buffer
     * @param entries the list to which the entry is added
     */
    private static void finalizeCurrentEntry(USNEntryJson entry, StringBuilder details,
            StringBuilder updates, List<USNEntryJson> entries) {
        if (details.length() > 0)
            entry.description = details.toString().trim();
        if (updates.length() > 0)
            entry.update_instructions = updates.toString().trim();
        entries.add(entry);
    }


    /**
     * Processes a single line of input and updates the fields of the given USNEntryJson object.
     * This method detects key patterns such as the published date, release versions, software
     * descriptions, and updates section-specific content (summary, details, instructions).
     *
     * @param entry the USNEntryJson object to populate
     * @param line the current line of text to process
     * @param inSummary true if the current line is within the summary section
     * @param inDetails true if the current line is within the details section
     * @param inUpdate true if the current line is within the update instructions section
     * @param detailsBuf buffer for accumulating lines in the details section
     * @param updateBuf buffer for accumulating lines in the update instructions section
     */
    private static void handleContentLine(USNEntryJson entry, String line, boolean inSummary,
            boolean inDetails, boolean inUpdate, StringBuilder detailsBuf,
            StringBuilder updateBuf) {

        Pattern datePattern = Pattern.compile(
                "(January|February|March|April|May|June|July|August|September|October|November|December) \\d{1,2}, \\d{4}");
        Pattern ubuntuVerPattern = Pattern.compile("-\\s*Ubuntu (\\d{2}\\.\\d{2}(?: LTS)?)");
        Pattern updatePattern = Pattern.compile("Ubuntu (\\d{2}\\.\\d{2}(?: LTS)?)\\s+(\\S.*)");
        Pattern cvePattern = Pattern.compile("(CVE-\\d{4}-\\d+)");
        Pattern softwareDescPattern = Pattern.compile("^-\\s*(.+):\\s*(.+)$");

        Matcher m;

        // Extract the published date if not yet set
        if (entry.published_date == null && (m = datePattern.matcher(line)).find()) {
            entry.published_date = parseDate(m.group(0));
        }

        // Extract Ubuntu release versions (e.g., "22.04", "20.04 LTS")
        m = ubuntuVerPattern.matcher(line);
        while (m.find()) {
            String version = m.group(1);
            if (!entry.releases.contains(version)) {
                entry.releases.add(version);
            }
        }

        // Also extract release versions from update lines
        m = updatePattern.matcher(line);
        while (m.find()) {
            String version = m.group(1);
            if (!entry.releases.contains(version)) {
                entry.releases.add(version);
            }
        }

        // Extract CVE identifiers
        m = cvePattern.matcher(line);
        while (m.find()) {
            String cve = m.group(1);
            if (!entry.cves.contains(cve)) {
                entry.cves.add(cve);
            }
        }

        // Extract software description (only the first occurrence)
        if ((m = softwareDescPattern.matcher(line)).find() && entry.software_description == null) {
            entry.software_description = m.group(1).trim() + ": " + m.group(2).trim();
        }

        // Accumulate section-specific content
        if (inSummary) {
            entry.summary += line.trim() + " ";
        } else if (inDetails) {
            detailsBuf.append(line.trim()).append(" ");
        } else if (inUpdate) {
            updateBuf.append(line.trim()).append(" ");
        }
    }

    

    /**
     * Safely converts null strings to "NA".
     *
     * @param s the input string
     * @return "NA" if input is null, otherwise the original string
     */
    private String nullToEmpty(String s) {
        return s != null ? s : "NA";
    }


    
    /**
     * Parses USN text entries from a buffered reader into structured objects.
     *
     * @param reader the BufferedReader of raw USN text
     * @return a list of structured USNEntryJson objects
     * @throws IOException if reading fails
     */
    public static List<USNEntryJson> parseUSNMessages(BufferedReader reader) throws IOException {
        List<USNEntryJson> entries = new ArrayList<>();
        USNEntryJson current = null;

        StringBuilder detailsBuf = new StringBuilder();
        StringBuilder updateBuf = new StringBuilder();
        boolean inSummary = false;
        boolean inDetails = false;
        boolean inUpdate = false;

        String line;
        while ((line = reader.readLine()) != null) {
            if (line.startsWith("Subject: [")) {
                if (current != null) {
                    finalizeCurrentEntry(current, detailsBuf, updateBuf, entries);
                }
                current = startNewEntry(line);
                if (current == null) {
                    logger.error("Skipping malformed USN entry due to parsing failure: {}", line);
                    continue;
                }
                inSummary = inDetails = inUpdate = false;
                detailsBuf.setLength(0);
                updateBuf.setLength(0);
            } else if (current != null) {
                if (line.startsWith("Summary:")) {
                    inSummary = true;
                    inDetails = inUpdate = false;
                    current.summary = "";
                    continue;
                } else if (line.startsWith("Software Description:")) {
                    inSummary = inDetails = inUpdate = false;
                    continue;
                } else if (line.startsWith("Details:")) {
                    inDetails = true;
                    inSummary = inUpdate = false;
                    continue;
                } else if (line.startsWith("Update instructions:")) {
                    inUpdate = true;
                    inDetails = inSummary = false;
                    continue;
                } else if (line.startsWith("References:")
                        || line.startsWith("Package Information:")) {
                    inSummary = inDetails = inUpdate = false;
                    continue;
                }

                handleContentLine(current, line, inSummary, inDetails, inUpdate, detailsBuf,
                        updateBuf);
            }
        }

        if (current != null) {
            finalizeCurrentEntry(current, detailsBuf, updateBuf, entries);
        }

        return entries;
    }



    /**
     * Parses a date string like "May 1, 2024" into ISO format ("2024-05-01").
     *
     * @param raw the raw date string
     * @return ISO 8601 date string or null if parsing fails
     */
    private static String parseDate(String raw) {
        try {
            return java.time.LocalDate.parse(raw,
                    java.time.format.DateTimeFormatter.ofPattern("MMMM d, yyyy", Locale.ENGLISH))
                    .toString();
        } catch (Exception e) {
            return null;
        }
    }


    
    
    /**
     * Outputs the list of USN entries in JSON format to stdout.
     *
     * @param entries the entries to serialize
     * @throws IOException if serialization fails
     */
    private void printAsJson(List<USNEntryJson> entries) throws IOException {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        mapper.writeValue(System.out, entries);
    }


    /**
     * Outputs the list of filtered USN entries in tab-separated values (TSV) format to standard output.
     * <p>
     * The output includes a header row followed by one line per entry. Each line contains the following fields:
     * <ul>
     *   <li>{@code id} – the USN identifier (e.g., USN-1234-1)</li>
     *   <li>{@code title} – the USN entry title</li>
     *   <li>{@code published_date} – the publication date in ISO 8601 format (e.g., 2024-05-18)</li>
     *   <li>{@code summary} – a summary of the vulnerability or update</li>
     *   <li>{@code severity} – the maximum severity level among associated CVEs</li>
     *   <li>{@code livepatch} – whether Canonical Livepatch is available ("yes", "no", or "NA")</li>
     * </ul>
     * <p>
     * Null or missing fields are replaced with {@code "NA"} to ensure consistency in the output.
     *
     * @param entries the list of USN entries to format and print
     */
    private void printAsTsv(List<USNEntryJson> entries) {
        // Print header row
        System.out.println("id\ttitle\tpublished_date\tsummary\tseverity\treboot\tlivepatch\tsevere_cves");

        // Filter out any remaining entries with null or empty ID
        List<USNEntryJson> validEntries = entries.stream()
            .filter(entry -> entry.id != null && !entry.id.trim().isEmpty())
            .collect(Collectors.toList());
            
        if (validEntries.size() != entries.size()) {
            logger.warn("Filtered out {} entries with null/empty ID from TSV output", 
                entries.size() - validEntries.size());
        }

        for (USNEntryJson entry : validEntries) {
            String id = nullToEmpty(entry.id);
            String title = nullToEmpty(entry.title);
            String date = nullToEmpty(entry.published_date);
            String summary = entry.summary != null
                    ? entry.summary.replace("\t", " ").replace("\n", " ").trim()
                    : "";
            String severity = nullToEmpty(entry.severity);
            String livepatch = nullToEmpty(entry.livepatch);
            String needsReboot = nullToEmpty(entry.needs_reboot);

            String severeCves = String.join(" ", entry.severeCves);

            System.out.printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s%n", id, title, date, summary,
                    severity, needsReboot, livepatch, severeCves);
        }
    }

    

   /**
     * Initializes a new USN entry based on the Subject line.
     *
     * @param line the Subject line from input
     * @return the initialized USNEntryJson object, or null if parsing fails
     */
    private static USNEntryJson startNewEntry(String line) {
        USNEntryJson entry = new USNEntryJson();
        
        // Log all Subject lines for debugging
        logger.debug("Processing Subject line: [{}]", line);
        
        // Expected pattern: "Subject: [USN-xxxx-x] Title"
        Pattern pattern = Pattern.compile("^Subject: \\[(USN-[\\d-]+)] (.+)$");
        Matcher m = pattern.matcher(line);
        
        if (m.find()) {
            entry.id = m.group(1);
            entry.title = m.group(2);
            logger.info("Successfully parsed USN entry: ID=[{}], Title=[{}]", entry.id, entry.title);
            return entry;
        } else {
            // Detailed analysis of why parsing failed
            logger.warn("=== SUBJECT LINE PARSE FAILURE ===");
            logger.warn("Failed Subject line: [{}]", line);
            logger.warn("Line length: {} characters", line.length());
            logger.warn("Starts with 'Subject: ': {}", line.startsWith("Subject: "));
            
            if (line.startsWith("Subject: ")) {
                String afterSubject = line.substring(9); // Remove "Subject: "
                logger.warn("After 'Subject: ': [{}]", afterSubject);
                logger.warn("Starts with '[': {}", afterSubject.startsWith("["));
                
                if (afterSubject.startsWith("[")) {
                    int closingBracket = afterSubject.indexOf(']');
                    if (closingBracket > 0) {
                        String bracketContent = afterSubject.substring(1, closingBracket);
                        logger.warn("Bracket content: [{}]", bracketContent);
                        logger.warn("Matches USN-pattern: {}", bracketContent.matches("USN-[\\d-]+"));
                    } else {
                        logger.warn("No closing bracket found");
                    }
                }
            }
            logger.warn("Expected pattern: Subject: [USN-xxxx-x] Title");
            logger.warn("=== END PARSE FAILURE ANALYSIS ===");
            return null;
        }
    }






}
