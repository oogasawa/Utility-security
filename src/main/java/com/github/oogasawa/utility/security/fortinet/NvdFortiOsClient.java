package com.github.oogasawa.utility.security.fortinet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Asks the National Vulnerability Database which CVEs affect a FortiOS version.
 *
 * <p>
 * The advisory feed of FortiGuard lists only the latest fifty advisories, so an advisory older
 * than that is found here. NVD answers for one version at a time, from the affected ranges that
 * Fortinet registered with each CVE. It accepts a publication period of at most 120 days, so a
 * longer period is asked for in pieces.
 * </p>
 */
public class NvdFortiOsClient {

    /** One CVE as NVD describes it. */
    public record Cve(String id, String published, String cvss, String severity,
            String description, String advisoryId) {
    }

    private static final String API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final int WINDOW_DAYS = 119;
    private static final Pattern ADVISORY = Pattern.compile("fortiguard\\.(?:fortinet\\.)?com/psirt/(FG-IR-\\d+-\\d+)");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TextFetcher fetcher;

    /**
     * Creates a client on the given fetcher.
     *
     * @param fetcher fetches the NVD responses, at most five requests in thirty seconds
     */
    public NvdFortiOsClient(TextFetcher fetcher) {
        this.fetcher = fetcher;
    }

    /**
     * Lists the CVEs published in a period that affect a FortiOS version.
     *
     * @param version the FortiOS version, such as {@code 7.4.6}
     * @param since the first day of the period
     * @param until the last day of the period
     * @return the CVEs
     * @throws IOException if NVD cannot be reached
     */
    public List<Cve> fetch(String version, LocalDate since, LocalDate until) throws IOException {
        List<Cve> result = new ArrayList<>();
        LocalDate from = since;
        while (!from.isAfter(until)) {
            LocalDate to = from.plusDays(WINDOW_DAYS);
            if (to.isAfter(until)) {
                to = until;
            }
            String url = API + "?virtualMatchString=cpe:2.3:o:fortinet:fortios:" + version
                    + "&pubStartDate=" + from + "T00:00:00.000&pubEndDate=" + to
                    + "T23:59:59.999&resultsPerPage=2000";
            result.addAll(parse(fetcher.get(url)));
            from = to.plusDays(1);
        }
        return result;
    }

    static List<Cve> parse(String json) throws IOException {
        List<Cve> out = new ArrayList<>();
        for (JsonNode v : MAPPER.readTree(json).path("vulnerabilities")) {
            JsonNode c = v.path("cve");
            String description = "";
            for (JsonNode d : c.path("descriptions")) {
                if ("en".equals(d.path("lang").asText())) {
                    description = d.path("value").asText("").replaceAll("\\s+", " ").strip();
                    break;
                }
            }
            String score = "";
            String severity = "";
            for (String key : new String[] {"cvssMetricV31", "cvssMetricV40", "cvssMetricV30"}) {
                JsonNode m = c.path("metrics").path(key).path(0).path("cvssData");
                if (!m.isMissingNode()) {
                    score = m.path("baseScore").asText("");
                    severity = m.path("baseSeverity").asText("");
                    break;
                }
            }
            String advisory = "";
            for (JsonNode r : c.path("references")) {
                Matcher m = ADVISORY.matcher(r.path("url").asText(""));
                if (m.find()) {
                    advisory = m.group(1);
                    break;
                }
            }
            String published = c.path("published").asText("");
            out.add(new Cve(c.path("id").asText(), published.length() >= 10
                    ? published.substring(0, 10) : published, score, severity, description,
                    advisory));
        }
        return out;
    }
}
