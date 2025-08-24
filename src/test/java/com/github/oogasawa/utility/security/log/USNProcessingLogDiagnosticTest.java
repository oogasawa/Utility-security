package com.github.oogasawa.utility.security.log;

import org.junit.jupiter.api.*;
import java.nio.file.*;
import java.util.*;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

public class USNProcessingLogDiagnosticTest {

    private static Path tempLogFile;

    @BeforeEach
    void setup() throws IOException {
        tempLogFile = Files.createTempFile("test-log", ".log");
    }

    @AfterEach
    void cleanup() throws IOException {
        if (Files.exists(tempLogFile)) {
            Files.deleteIfExists(tempLogFile);
        }
    }

    @Test
    void testNullIdDetection() throws IOException {
        String logContent = "2024-01-15 10:30:45 ERROR - USN ID cannot be null or empty\n" +
                           "2024-01-15 10:30:46 INFO - Processing normal entry\n";
        Files.write(tempLogFile, logContent.getBytes());

        List<String> problematic = USNProcessingLogDiagnostic.extractProblematicEntries(tempLogFile);
        
        assertEquals(1, problematic.size());
        assertTrue(problematic.get(0).contains("USN ID cannot be null or empty"));
    }

    @Test
    void testUnknownSeverityDetection() throws IOException {
        String logContent = "2024-01-15 10:30:45 WARN - Severity is unknown due to parsing failure\n" +
                           "2024-01-15 10:30:46 INFO - Successfully processed USN-1234-1\n";
        Files.write(tempLogFile, logContent.getBytes());

        List<String> problematic = USNProcessingLogDiagnostic.extractProblematicEntries(tempLogFile);
        
        assertEquals(1, problematic.size());
        assertTrue(problematic.get(0).toLowerCase().contains("severity"));
        assertTrue(problematic.get(0).toLowerCase().contains("unknown"));
    }

    @Test
    void testParseFailureDetection() throws IOException {
        String logContent = "2024-01-15 10:30:45 WARN - === SUBJECT LINE PARSE FAILURE ===\n" +
                           "2024-01-15 10:30:46 DEBUG - Pattern match successful\n";
        Files.write(tempLogFile, logContent.getBytes());

        List<String> problematic = USNProcessingLogDiagnostic.extractProblematicEntries(tempLogFile);
        
        assertEquals(1, problematic.size());
        assertTrue(problematic.get(0).contains("SUBJECT LINE PARSE FAILURE"));
    }

    @Test
    void testHttpErrorDetection() throws IOException {
        String logContent = "2024-01-15 10:30:45 ERROR - HTTP error 404 while fetching USN\n" +
                           "2024-01-15 10:30:46 ERROR - Connection timed out after 30 seconds\n" +
                           "2024-01-15 10:30:47 INFO - Successfully connected\n";
        Files.write(tempLogFile, logContent.getBytes());

        List<String> problematic = USNProcessingLogDiagnostic.extractProblematicEntries(tempLogFile);
        
        assertEquals(2, problematic.size());
    }

    @Test
    void testIsProblematicMethod() {
        assertTrue(USNProcessingLogDiagnostic.isProblematic("ERROR - USN ID cannot be null or empty"));
        assertTrue(USNProcessingLogDiagnostic.isProblematic("WARN - Severity is UNKNOWN"));
        assertTrue(USNProcessingLogDiagnostic.isProblematic("WARN - === SUBJECT LINE PARSE FAILURE ==="));
        assertTrue(USNProcessingLogDiagnostic.isProblematic("ERROR - HTTP error 404"));
        assertTrue(USNProcessingLogDiagnostic.isProblematic("ERROR - Connection timed out"));
        
        assertFalse(USNProcessingLogDiagnostic.isProblematic("INFO - Successfully processed USN"));
        assertFalse(USNProcessingLogDiagnostic.isProblematic("DEBUG - Normal log entry"));
    }

    @Test
    void testCategorizeIssue() {
        assertEquals("NULL_ID", USNProcessingLogDiagnostic.categorizeIssue("ERROR - USN ID cannot be null or empty"));
        assertEquals("UNKNOWN_SEVERITY", USNProcessingLogDiagnostic.categorizeIssue("WARN - severity is unknown"));
        assertEquals("PARSE_FAILURE", USNProcessingLogDiagnostic.categorizeIssue("WARN - === SUBJECT LINE PARSE FAILURE ==="));
        assertEquals("HTTP_ERROR", USNProcessingLogDiagnostic.categorizeIssue("ERROR - HTTP error 404"));
        assertEquals("OTHER", USNProcessingLogDiagnostic.categorizeIssue("INFO - Normal log entry"));
    }

    @Test
    void testGenerateSummaryReport() throws IOException {
        String logContent = "2024-01-15 10:30:45 ERROR - USN ID cannot be null or empty\n" +
                           "2024-01-15 10:30:46 WARN - Severity is unknown\n" +
                           "2024-01-15 10:30:47 WARN - === SUBJECT LINE PARSE FAILURE ===\n" +
                           "2024-01-15 10:30:48 ERROR - HTTP error 404\n" +
                           "2024-01-15 10:30:49 INFO - Successfully processed USN\n";
        Files.write(tempLogFile, logContent.getBytes());

        String report = USNProcessingLogDiagnostic.generateSummaryReport(tempLogFile);
        
        assertTrue(report.contains("USN Processing Log Diagnostic Summary"));
        assertTrue(report.contains("Total problematic entries: 4"));
        assertTrue(report.contains("Null ID issues: 1"));
        assertTrue(report.contains("Unknown severity issues: 1"));
        assertTrue(report.contains("Parse failure issues: 1"));
        assertTrue(report.contains("HTTP error issues: 1"));
    }

    @Test
    void testEmptyLogFile() throws IOException {
        Files.write(tempLogFile, "".getBytes());

        List<String> problematic = USNProcessingLogDiagnostic.extractProblematicEntries(tempLogFile);
        String report = USNProcessingLogDiagnostic.generateSummaryReport(tempLogFile);
        
        assertEquals(0, problematic.size());
        assertTrue(report.contains("Total problematic entries: 0"));
    }
}