package com.github.oogasawa.utility.security.fortinet;

import java.util.List;
import java.util.Map;

/**
 * One FortiGuard PSIRT advisory that lists FortiOS as affected.
 *
 * @param id the advisory identifier, such as {@code FG-IR-26-182}
 * @param title the title of the advisory
 * @param published the initial release date, as {@code yyyy-MM-dd}
 * @param cves the CVE identifiers
 * @param cvss the CVSS v3 base score, or an empty string
 * @param severity the severity the advisory states, such as {@code HIGH}
 * @param answers the answer for each FortiOS version asked about
 * @param remediations the remediation line for each FortiOS version asked about
 * @param url the address of the advisory
 */
public record FortinetAdvisory(String id, String title, String published, List<String> cves,
        String cvss, String severity, Map<String, FortiOsVersionMatcher.Answer> answers,
        Map<String, String> remediations, String url) {

    /** Tells whether any version asked about is affected, or needs a person's check. */
    public boolean concernsAnyVersion() {
        return answers.values().stream()
                .anyMatch(a -> a != FortiOsVersionMatcher.Answer.NOT_AFFECTED);
    }
}
