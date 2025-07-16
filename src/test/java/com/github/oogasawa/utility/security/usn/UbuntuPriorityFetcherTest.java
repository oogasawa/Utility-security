package com.github.oogasawa.utility.security.usn;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

public class UbuntuPriorityFetcherTest {



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

  

    
}
