package com.github.oogasawa.utility.security.log;

import org.junit.jupiter.api.Test;

import java.nio.file.attribute.FileTime;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link LogFileNameHelper}.
 */
class LogFileNameHelperTest {

    /**
     * Tests that a valid 8-digit date is correctly extracted from a file name.
     */
    @Test
    void testExtractDateFromFileName() {
        assertEquals("20250622", LogFileNameHelper.extractDateFromFileName("auth.log-20250622"));
        assertEquals("20250610", LogFileNameHelper.extractDateFromFileName("access.20250610.log"));
        assertEquals("20250101", LogFileNameHelper.extractDateFromFileName("prefix-20250101-suffix.log"));
    }

    /**
     * Tests that no date is returned if the file name does not contain 8 digits.
     */
    @Test
    void testExtractDateFromFileName_NoDate() {
        assertNull(LogFileNameHelper.extractDateFromFileName("auth.log"));
        assertNull(LogFileNameHelper.extractDateFromFileName("error.log.bak"));
    }

    /**
     * Tests date conversion from FileTime to yyyyMMdd format.
     */
    @Test
    void testGetDateFromTimestamp() {
        Instant instant = Instant.parse("2025-06-22T12:00:00Z");
        FileTime fileTime = FileTime.from(instant);
        assertEquals("20250622", LogFileNameHelper.getDateFromTimestamp(fileTime));
    }

    /**
     * Tests filename generation when the original name does not already contain the date.
     */
    @Test
    void testBuildNewFileName_DateNotInName() {
        String result = LogFileNameHelper.buildNewFileName("auth.log", "20250622", "nigscHP2");
        assertEquals("auth.log_20250622_nigscHP2", result);
    }

    /**
     * Tests filename generation when the original name already contains the date,
     * to avoid duplication of the date in the new name.
     */
    @Test
    void testBuildNewFileName_DateAlreadyInName() {
        String result = LogFileNameHelper.buildNewFileName("auth.log-20250622", "20250622", "nigscHP2");
        assertEquals("auth.log-20250622_nigscHP2", result);
    }

    /**
     * Tests filename generation when the original name includes a different date than the one to append.
     */
    @Test
    void testBuildNewFileName_ContainsDifferentDate() {
        String result = LogFileNameHelper.buildNewFileName("auth.log-20250615", "20250622", "nigscHP2");
        // Not matching exactly, so date will be added
        assertEquals("auth.log-20250615_20250622_nigscHP2", result);
    }
}
