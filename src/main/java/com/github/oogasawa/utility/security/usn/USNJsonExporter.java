package com.github.oogasawa.utility.security.usn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.*;
import java.nio.file.*;
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

    /**
     * Enumeration representing severity levels for CVEs, in increasing order of seriousness.
     */
    public enum PriorityLevel {
        LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);

        private final int level;

        PriorityLevel(int level) {
            this.level = level;
        }

        public int level() {
            return level;
        }

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
        try (BufferedReader reader = Files.newBufferedReader(inputPath)) {
            List<USNEntryJson> entries = parseUSNMessages(reader);

            List<USNEntryJson> filtered = entries.stream()
                .filter(this::appliesToUbuntu2404)
                .filter(this::isGenericKernelReport)
                .collect(Collectors.toList());

            for (USNEntryJson entry : filtered) {
                assignMaxSeverity(entry);
                try {
                    Document doc = LivepatchHtmlFetcher.fetchUsnDocument(entry.id);
                    determineLivepatchAvailability(entry, doc);
                    determineRebootRequirement(entry, doc); 
                } catch (IOException e) {
                    entry.livepatch = "NA";
                    entry.needs_reboot = "NA";
                }
            }

            if ("tsv".equalsIgnoreCase(format)) {
                printAsTsv(filtered);
            } else {
                printAsJson(filtered);
            }

        } catch (IOException e) {
            System.err.println("Failed to process security report file: " + e.getMessage());
        }
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
     * Assigns the highest severity level among the entry's CVEs to the entry itself.
     *
     * @param entry the USN entry to modify
     */
    private void assignMaxSeverity(USNEntryJson entry) {
        logger.info(String.format("%s, %s, %s", entry.id, entry.title, entry.cves));
        
        List<PriorityLevel> levels = entry.cves.stream().map(this::fetchPrioritySafely)
                .filter(Objects::nonNull).collect(Collectors.toList());

        logger.info(String.format("levels.size() = %d", levels.size()));
        
        Optional<PriorityLevel> max =
                levels.stream().max(Comparator.comparingInt(PriorityLevel::level));

        entry.severity = max.map(PriorityLevel::nameCapitalized).orElse("Unknown");
    }

    /**
     * Determines whether Canonical Livepatch is available for a given USN entry.
     *
     * @param entry the USN entry to evaluate
     * @param doc   the HTML document fetched for the USN
     */
    private void determineLivepatchAvailability(USNEntryJson entry, Document doc) {
        String bodyText = doc.body().text().toLowerCase();
        if (bodyText.contains("canonical livepatch is available")) {
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
     * @param doc the parsed HTML document for the corresponding USN
     */
    private void determineRebootRequirement(USNEntryJson entry, Document doc) {
        String text = doc.body().text().toLowerCase();
        if (text.contains("a reboot is required")
                || text.contains("you need to reboot your computer")) {
            entry.needs_reboot = "yes";
        } else {
            entry.needs_reboot = "no";
        }
    }

    

    /**
     * Determines whether the given USN entry is a generic kernel report,
     * excluding cloud, OEM, and other specific variants.
     *
     * @param entry the USN entry to evaluate
     * @return true if the entry is generic, false otherwise
     */
    private boolean isGenericKernelReport(USNEntryJson entry) {
        String title = entry.title != null ? entry.title : "";
        return !(title.contains("(GKE)") || title.contains("(AWS)") || title.contains("(Azure)")
                || title.contains("(NVIDIA)") || title.contains("(Real-time)")
                || title.contains("(OEM)") || title.contains("(Raspberry Pi)"));
    }


    /**
     * Attempts to retrieve the Ubuntu-assigned priority level for the given CVE ID.
     * <p>
     * This method queries the Ubuntu CVE Tracker to determine the severity of the specified CVE.
     * If the request fails (due to network issues, malformed responses, or unavailable data),
     * the method logs a warning and returns {@code null} instead of throwing an exception.
     *
     * @param cveId the CVE identifier (e.g., "CVE-2024-12345")
     * @return a {@link PriorityLevel} representing the severity assigned by Ubuntu,
     *         or {@code null} if the priority could not be determined
     */
    private PriorityLevel fetchPrioritySafely(String cveId) {
        try {
            String rawPriority = UbuntuPriorityFetcher.fetchUbuntuPriority(cveId);
            logger.info(String.format("rawPriority: %s, %s", rawPriority, cveId));
            return PriorityLevel.fromString(rawPriority);
        } catch (Exception e) {
            logger.warn("Failed to fetch priority for CVE {}: {}", cveId, e.getMessage());
            return null;
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
        System.out.println("id\ttitle\tpublished_date\tsummary\tseverity\treboot\tlivepatch");

        for (USNEntryJson entry : entries) {
            String id = nullToEmpty(entry.id);
            String title = nullToEmpty(entry.title);
            String date = nullToEmpty(entry.published_date);
            String summary = entry.summary != null
                    ? entry.summary.replace("\t", " ").replace("\n", " ").trim()
                    : "";
            String severity = nullToEmpty(entry.severity);
            String livepatch = nullToEmpty(entry.livepatch);
            String needsReboot = nullToEmpty(entry.needs_reboot);

            System.out.printf("%s\t%s\t%s\t%s\t%s\t%s\t%s%n", id, title, date, summary, severity, needsReboot, livepatch);
        }
    }

    

   /**
     * Initializes a new USN entry based on the Subject line.
     *
     * @param line the Subject line from input
     * @return the initialized USNEntryJson object
     */
    private static USNEntryJson startNewEntry(String line) {
        USNEntryJson entry = new USNEntryJson();
        Matcher m = Pattern.compile("^Subject: \\[(USN-[\\d-]+)] (.+)$").matcher(line);
        if (m.find()) {
            entry.id = m.group(1);
            entry.title = m.group(2);
        }
        return entry;
    }






}
