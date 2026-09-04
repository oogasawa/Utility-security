package com.github.oogasawa.utility.security.usn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the retry schedule of {@link UbuntuSecurityHttpClient}.
 *
 * <p>
 * These tests touch no external service. They verify the wait computed before each attempt, which
 * is the part of the class that decides how gently the server is treated.
 * </p>
 */
@DisplayName("UbuntuSecurityHttpClient — the wait before each attempt")
public class UbuntuSecurityHttpClientTest {

    @Test
    @DisplayName("The first attempt waits the request interval")
    void waitMillisBefore_firstAttempt_returnsTheRequestInterval() {
        assertEquals(UbuntuSecurityHttpClient.REQUEST_INTERVAL_MS,
                UbuntuSecurityHttpClient.waitMillisBefore(1));
    }

    @Test
    @DisplayName("Every retry adds the retry increment to the previous wait")
    void waitMillisBefore_eachRetry_addsTheRetryIncrement() {
        for (int attempt = 2; attempt <= UbuntuSecurityHttpClient.MAX_RETRIES; attempt++) {
            long previous = UbuntuSecurityHttpClient.waitMillisBefore(attempt - 1);
            long current = UbuntuSecurityHttpClient.waitMillisBefore(attempt);
            assertEquals(UbuntuSecurityHttpClient.RETRY_INCREMENT_MS, current - previous,
                    "attempt " + attempt);
        }
    }

    @Test
    @DisplayName("The waits of the whole schedule are 10s through 100s")
    void waitMillisBefore_wholeSchedule_runsFromTenToOneHundredSeconds() {
        assertEquals(10000L, UbuntuSecurityHttpClient.waitMillisBefore(1));
        assertEquals(100000L, UbuntuSecurityHttpClient.waitMillisBefore(10));
        assertEquals(10, UbuntuSecurityHttpClient.MAX_RETRIES);
    }

    @Test
    @DisplayName("Exhausting every attempt takes between nine and ten minutes of waiting")
    void waitMillisBefore_everyAttempt_addsUpToNineOrTenMinutes() {
        long total = 0;
        for (int attempt = 1; attempt <= UbuntuSecurityHttpClient.MAX_RETRIES; attempt++) {
            total += UbuntuSecurityHttpClient.waitMillisBefore(attempt);
        }
        assertEquals(550000L, total);
    }

    @Test
    @DisplayName("No attempt waits less than the request interval")
    void waitMillisBefore_everyAttempt_waitsAtLeastTheRequestInterval() {
        for (int attempt = 1; attempt <= UbuntuSecurityHttpClient.MAX_RETRIES; attempt++) {
            assertTrue(UbuntuSecurityHttpClient.waitMillisBefore(attempt)
                    >= UbuntuSecurityHttpClient.REQUEST_INTERVAL_MS, "attempt " + attempt);
        }
    }

    @Test
    @DisplayName("A blank URL is rejected before any request is issued")
    void fetchJson_blankUrl_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> UbuntuSecurityHttpClient.fetchJson("   "));
    }
}
