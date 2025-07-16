package com.github.oogasawa.utility.security.log;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link LogFileFilter} class.
 *
 * <p>This test suite verifies that the {@code isTarget(String fileName)} method correctly
 * identifies known log file name patterns and rejects unrelated file names.</p>
 */
class LogFileFilterTest {

    /**
     * Tests that Apache access log files and their rotated forms are recognized.
     */
    @Test
    @DisplayName("Should match Apache access.log and rotated variants")
    void testApacheAccessLog() {
        assertTrue(LogFileFilter.isTarget("access.log"));
        assertTrue(LogFileFilter.isTarget("access.log.1"));
        assertTrue(LogFileFilter.isTarget("access.log-20250621.gz"));
    }

    /**
     * Tests that Apache error log files and their rotated forms are recognized.
     */
    @Test
    @DisplayName("Should match Apache error.log and rotated variants")
    void testApacheErrorLog() {
        assertTrue(LogFileFilter.isTarget("error.log"));
        assertTrue(LogFileFilter.isTarget("error.log.1"));
        assertTrue(LogFileFilter.isTarget("error.log-20250620.gz"));
    }

    /**
     * Tests that common system logs like auth.log, kern.log, and syslog are recognized.
     */
    @Test
    @DisplayName("Should match system logs like auth, kern, syslog")
    void testSystemLogs() {
        assertTrue(LogFileFilter.isTarget("auth.log"));
        assertTrue(LogFileFilter.isTarget("syslog-20250621"));
        assertTrue(LogFileFilter.isTarget("kern.log.2.gz"));
    }

    /**
     * Tests that journal-export log files are recognized.
     */
    @Test
    @DisplayName("Should match journal-export logs")
    void testJournalExportLogs() {
        assertTrue(LogFileFilter.isTarget("journal-20250620.log"));
        assertTrue(LogFileFilter.isTarget("journal-20250620.log.1.gz"));
    }

    /**
     * Tests that package management log files are recognized.
     */
    @Test
    @DisplayName("Should match package management logs")
    void testPackageLogs() {
        assertTrue(LogFileFilter.isTarget("dpkg.log"));
        assertTrue(LogFileFilter.isTarget("alternatives.log"));
        assertTrue(LogFileFilter.isTarget("apport.log"));
        assertTrue(LogFileFilter.isTarget("ubuntu-advantage.log"));
    }

    /**
     * Tests that sysstat-related log files (saNN and sarNN) are recognized.
     */
    @Test
    @DisplayName("Should match sysstat logs")
    void testSysstatLogs() {
        assertTrue(LogFileFilter.isTarget("sa14"));
        assertTrue(LogFileFilter.isTarget("sar21"));
    }

    /**
     * Tests that APT and unattended upgrade log files are recognized.
     */
    @Test
    @DisplayName("Should match APT and unattended upgrade logs")
    void testAptLogs() {
        assertTrue(LogFileFilter.isTarget("history.log"));
        assertTrue(LogFileFilter.isTarget("term.log"));
        assertTrue(LogFileFilter.isTarget("unattended-upgrades.log"));
        assertTrue(LogFileFilter.isTarget("unattended-upgrades-dpkg.log"));
    }

    /**
     * Tests that unrelated file names do not match any log patterns.
     */
    @Test
    @DisplayName("Should NOT match unrelated files")
    void testNonMatchingFiles() {
        assertFalse(LogFileFilter.isTarget("notes.txt"));
        assertFalse(LogFileFilter.isTarget("README.md"));
        assertFalse(LogFileFilter.isTarget("image.png"));
        assertFalse(LogFileFilter.isTarget("random_output_20250621.txt"));
    }
}
