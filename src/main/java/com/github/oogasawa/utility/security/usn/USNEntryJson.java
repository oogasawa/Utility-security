package com.github.oogasawa.utility.security.usn;

import java.util.ArrayList;
import java.util.List;

/**
 * Mutable data holder representing a single Ubuntu Security Notice entry enriched with metadata
 * required for JSON/TSV export.
 */
public class USNEntryJson {
    public String id;
    public String title;
    public String published_date;
    public String summary;
    public String software_description;
    public String description;
    public String update_instructions;
    public List<String> cves = new ArrayList<>();
    public List<String> releases = new ArrayList<>();
    public String severity; 
     public String livepatch = "auto"; // "yes", "no", or "NA"
    public String needs_reboot; // "yes", "no"

    /**
     * Identifiers of the notices that were merged into this one because they share its USN number
     * and differ only in the suffix. Empty when nothing was merged.
     */
    public List<String> mergedNoticeIds = new ArrayList<>();

    /** CVEs of this notice whose Ubuntu priority is High or Critical. */
    public List<String> severeCves = new ArrayList<>();
}



