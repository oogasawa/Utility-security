package com.github.oogasawa.utility.security.usn;


import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import java.io.IOException;

/**
 * Integration-style tests that exercise {@link UbuntuPriorityFetcher} against live Ubuntu trackers.
 */
public class UbuntuPriorityFetcherTest {


    /**
     * Ensures that the live Ubuntu tracker returns a non-empty priority for a recent CVE.
     */
    @Test
    public void testFetchUbuntuPriority_liveAccess() throws Exception {
        String cveId = "CVE-2025-46727";
        String priority = UbuntuPriorityFetcher.fetchUbuntuPriority(cveId);

        // Priority should not be null or empty
        assertNotNull(priority, "Ubuntu priority should not be null from live page");
        assertFalse(priority.isBlank(), "Ubuntu priority should not be blank");

        // Optionally: check that it's a known valid value
        assertTrue(
            priority.equalsIgnoreCase("Low") ||
            priority.equalsIgnoreCase("Medium") ||
            priority.equalsIgnoreCase("High") ||
            priority.equalsIgnoreCase("Critical") ||
            priority.equalsIgnoreCase("Unknown"),
            "Priority must be one of the expected values"
        );

        System.out.println("Live Ubuntu priority for " + cveId + ": " + priority);
    }

    /**
     * Confirms that non-existent CVEs are reported with the {@code Unknown} priority value.
     */
    @Test
    public void testFetchUbuntuPriority_nonExistentCVE() throws Exception {
        String cveId = "CVE-1999-99999";
        String priority = UbuntuPriorityFetcher.fetchUbuntuPriority(cveId);
        
        assertEquals("Unknown", priority, 
            "Non-existent CVE should return 'Unknown' priority");
    }
    
    /**
     * Verifies retry behavior by asserting that failures mention the number of attempts or yield a
     * valid priority when the request succeeds.
     */
    @Test
    @Timeout(value = 35) // Should complete within 35 seconds even with retries
    public void testFetchUbuntuPriority_retriesOnFailure() throws Exception {
        // This test verifies the retry mechanism is working
        // We use a real CVE to ensure the test is meaningful
        String cveId = "CVE-2024-12345";
        
        try {
            String priority = UbuntuPriorityFetcher.fetchUbuntuPriority(cveId);
            // If successful, verify we got a valid response
            assertNotNull(priority);
            assertTrue(priority.equals("Unknown") || 
                      priority.equals("Low") || 
                      priority.equals("Medium") || 
                      priority.equals("High") || 
                      priority.equals("Critical"));
        } catch (IOException e) {
            // If it fails after all retries, verify the error message mentions retries
            assertTrue(e.getMessage().contains("after 3 attempts"),
                "Error message should indicate retry attempts were made");
        }
    }
    
    /**
     * Checks that the fetcher accepts well-formed CVE identifiers and handles network failures.
     */
    @Test
    public void testFetchUbuntuPriority_validCVEFormat() throws Exception {
        // Test with a known CVE that should exist
        String cveId = "CVE-2024-39282"; // From the README example
        
        try {
            String priority = UbuntuPriorityFetcher.fetchUbuntuPriority(cveId);
            assertNotNull(priority, "Priority should not be null");
            assertFalse(priority.isBlank(), "Priority should not be blank");
        } catch (IOException e) {
            // Even if network fails, verify proper error handling
            assertNotNull(e.getMessage());
            assertTrue(e.getMessage().contains("CVE-2024-39282"));
        }
    }
    
}
