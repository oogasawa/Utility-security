package com.github.oogasawa.utility.security.usn;

/**
 * Represents detailed CVE information including severity and CVSS score.
 */
public class CVEEntry {

    /**
     * CVE identifier (e.g., CVE-2024-12345)
     * 
     * These fields are declared public for compatibility with Jackson's
     * serialization and deserialization mechanisms, which can access public
     * fields directly when getters and setters are not provided.
     */
    public String id;

    /**
     * CVSS base score (e.g., 7.8, 9.1), or null if not available
     */
    public Double cvssScore;

    /**
     * Severity label (e.g., "Low", "Medium", "High", "Critical")
     */
    public String severity;

    /**
     * Default constructor required for Jackson deserialization
     */
    public CVEEntry() {}

    /**
     * Constructs a CVEEntry with the specified ID, CVSS score, and severity level.
     */
    public CVEEntry(String id, Double cvssScore, String severity) {
        this.id = id;
        this.cvssScore = cvssScore;
        this.severity = severity;
    }

    @Override
    public String toString() {
        return "CVEEntry{id='%s', cvssScore=%.1f, severity='%s'}"
                .formatted(id, cvssScore != null ? cvssScore : 0.0, severity);
    }
}

