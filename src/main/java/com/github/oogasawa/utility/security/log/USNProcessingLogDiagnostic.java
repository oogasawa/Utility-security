package com.github.oogasawa.utility.security.log;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A diagnostic utility for analyzing USN processing logs to identify
 * data quality issues such as null IDs, unknown severities, and parsing failures.
 */
public class USNProcessingLogDiagnostic {
    
    private static final Pattern NULL_ID_PATTERN = 
        Pattern.compile(".*USN ID cannot be null or empty.*");
    
    private static final Pattern UNKNOWN_SEVERITY_PATTERN = 
        Pattern.compile(".*severity.*unknown.*", Pattern.CASE_INSENSITIVE);
    
    private static final Pattern PARSE_FAILURE_PATTERN = 
        Pattern.compile(".*SUBJECT LINE PARSE FAILURE.*");
    
    private static final Pattern HTTP_ERROR_PATTERN = 
        Pattern.compile(".*(HTTP error|Connection timed out|IOException).*");
    
    private static final Pattern EMPTY_ENTRY_PATTERN = 
        Pattern.compile(".*Empty USN entry detected.*");

    /**
     * Analyzes a log file and extracts entries that indicate potential issues
     * with USN processing, such as null IDs, unknown severities, or parsing failures.
     *
     * @param logFile the path to the log file to analyze
     * @return a list of log lines that indicate potential issues
     * @throws IOException if an error occurs reading the log file
     */
    public static List<String> extractProblematicEntries(Path logFile) throws IOException {
        return Files.lines(logFile)
            .filter(USNProcessingLogDiagnostic::isProblematic)
            .collect(Collectors.toList());
    }

    /**
     * Determines if a log line indicates a potential issue with USN processing.
     *
     * @param logLine the log line to check
     * @return true if the line indicates a potential issue, false otherwise
     */
    public static boolean isProblematic(String logLine) {
        return NULL_ID_PATTERN.matcher(logLine).matches() ||
               UNKNOWN_SEVERITY_PATTERN.matcher(logLine).matches() ||
               PARSE_FAILURE_PATTERN.matcher(logLine).matches() ||
               HTTP_ERROR_PATTERN.matcher(logLine).matches() ||
               EMPTY_ENTRY_PATTERN.matcher(logLine).matches();
    }

    /**
     * Categorizes a problematic log line by the type of issue it represents.
     *
     * @param logLine the log line to categorize
     * @return a string describing the category of the issue
     */
    public static String categorizeIssue(String logLine) {
        if (NULL_ID_PATTERN.matcher(logLine).matches()) {
            return "NULL_ID";
        } else if (UNKNOWN_SEVERITY_PATTERN.matcher(logLine).matches()) {
            return "UNKNOWN_SEVERITY";
        } else if (PARSE_FAILURE_PATTERN.matcher(logLine).matches()) {
            return "PARSE_FAILURE";
        } else if (HTTP_ERROR_PATTERN.matcher(logLine).matches()) {
            return "HTTP_ERROR";
        } else if (EMPTY_ENTRY_PATTERN.matcher(logLine).matches()) {
            return "EMPTY_ENTRY";
        }
        return "OTHER";
    }

    /**
     * Provides a summary report of issues found in the log.
     *
     * @param logFile the path to the log file to analyze
     * @return a formatted summary string
     * @throws IOException if an error occurs reading the log file
     */
    public static String generateSummaryReport(Path logFile) throws IOException {
        List<String> problematicEntries = extractProblematicEntries(logFile);
        
        long nullIdCount = problematicEntries.stream()
            .filter(line -> NULL_ID_PATTERN.matcher(line).matches())
            .count();
        
        long unknownSeverityCount = problematicEntries.stream()
            .filter(line -> UNKNOWN_SEVERITY_PATTERN.matcher(line).matches())
            .count();
        
        long parseFailureCount = problematicEntries.stream()
            .filter(line -> PARSE_FAILURE_PATTERN.matcher(line).matches())
            .count();
        
        long httpErrorCount = problematicEntries.stream()
            .filter(line -> HTTP_ERROR_PATTERN.matcher(line).matches())
            .count();
        
        long emptyEntryCount = problematicEntries.stream()
            .filter(line -> EMPTY_ENTRY_PATTERN.matcher(line).matches())
            .count();

        StringBuilder report = new StringBuilder();
        report.append("=== USN Processing Log Diagnostic Summary ===\n");
        report.append(String.format("Total problematic entries: %d\n", problematicEntries.size()));
        report.append(String.format("  - Null ID issues: %d\n", nullIdCount));
        report.append(String.format("  - Unknown severity issues: %d\n", unknownSeverityCount));
        report.append(String.format("  - Parse failure issues: %d\n", parseFailureCount));
        report.append(String.format("  - HTTP error issues: %d\n", httpErrorCount));
        report.append(String.format("  - Empty entry issues: %d\n", emptyEntryCount));
        
        return report.toString();
    }
}