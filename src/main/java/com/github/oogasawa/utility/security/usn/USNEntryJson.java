package com.github.oogasawa.utility.security.usn;

import java.util.ArrayList;
import java.util.List;

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
    public List<CVEEntry> cve_details = new ArrayList<>();
    public String severity; 
     public String livepatch = "auto"; // "yes", "no", or "auto"
}




