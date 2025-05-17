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

public class USNJsonExporter {

    private static final Logger logger = LoggerFactory.getLogger(USNJsonExporter.class);

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
                } catch (IOException e) {
                    entry.livepatch = "NA";
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
    



    private boolean appliesToUbuntu2404(USNEntryJson entry) {
        return entry.releases.stream()
                .anyMatch(rel -> rel.equals("24.04") || rel.equals("24.04 LTS"));
    }



    private void assignMaxSeverity(USNEntryJson entry) {
        logger.info(String.format("%s, %s, %s", entry.id, entry.title, entry.cves));
        
        List<PriorityLevel> levels = entry.cves.stream().map(this::fetchPrioritySafely)
                .filter(Objects::nonNull).collect(Collectors.toList());

        logger.info(String.format("levels.size() = %d", levels.size()));
        
        Optional<PriorityLevel> max =
                levels.stream().max(Comparator.comparingInt(PriorityLevel::level));

        entry.severity = max.map(PriorityLevel::nameCapitalized).orElse("Unknown");
    }


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
    
    private boolean isGenericKernelReport(USNEntryJson entry) {
        String title = entry.title != null ? entry.title : "";
        return !(title.contains("(GKE)") || title.contains("(AWS)") || title.contains("(Azure)")
                || title.contains("(NVIDIA)") || title.contains("(Real-time)")
                || title.contains("(OEM)") || title.contains("(Raspberry Pi)"));
    }

    
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

    private void printAsJson(List<USNEntryJson> entries) throws IOException {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        mapper.writeValue(System.out, entries);
    }


    private void printAsTsv(List<USNEntryJson> entries) {
        // Print header row
        System.out.println("id\ttitle\tpublished_date\tsummary\tseverity\tlivepatch");

        for (USNEntryJson entry : entries) {
            String id = nullToEmpty(entry.id);
            String title = nullToEmpty(entry.title);
            String date = nullToEmpty(entry.published_date);
            String summary = entry.summary != null
                    ? entry.summary.replace("\t", " ").replace("\n", " ").trim()
                    : "";
            String severity = nullToEmpty(entry.severity);
            String livepatch = nullToEmpty(entry.livepatch);

            System.out.printf("%s\t%s\t%s\t%s\t%s\t%s%n", id, title, date, summary, severity, livepatch);
        }
    }

    private String nullToEmpty(String s) {
        return s != null ? s : "NA";
    }

    

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

    private static USNEntryJson startNewEntry(String line) {
        USNEntryJson entry = new USNEntryJson();
        Matcher m = Pattern.compile("^Subject: \\[(USN-[\\d-]+)] (.+)$").matcher(line);
        if (m.find()) {
            entry.id = m.group(1);
            entry.title = m.group(2);
        }
        return entry;
    }

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



    private static String parseDate(String raw) {
        try {
            return java.time.LocalDate.parse(raw,
                    java.time.format.DateTimeFormatter.ofPattern("MMMM d, yyyy", Locale.ENGLISH))
                    .toString();
        } catch (Exception e) {
            return null;
        }
    }


    private static String getSeverityLabel(double score) {
        if (score >= 9.0)
            return "Critical";
        else if (score >= 7.0)
            return "High";
        else if (score >= 4.0)
            return "Medium";
        else if (score > 0.0)
            return "Low";
        else
            return "None";
    }



    private static boolean isMoreSevere(double score, String currentSeverity) {
        Map<String, Integer> severityRank =
                Map.of("None", 0, "Low", 1, "Medium", 2, "High", 3, "Critical", 4);
        return severityRank.getOrDefault(getSeverityLabel(score), 0) > severityRank
                .getOrDefault(currentSeverity, 0);
    }



}
