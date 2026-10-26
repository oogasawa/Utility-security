package com.github.oogasawa.utility.security.fortinet;

import java.io.IOException;
import java.io.PrintStream;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Writes the TSV report of FortiOS advisories, in the columns of the patch history sheet for
 * CVEs other than Ubuntu's.
 */
public class FortinetReporter {

    /** Header line of the report. */
    public static final String HEADER =
            "id\tcategory\tcve\tpublished_date\ttarget\tseverity\tcvss\tfixed\tsummary";

    private final FortinetPsirtClient client;
    private final NvdFortiOsClient nvd;

    /**
     * Creates a reporter that reads the advisory feed only.
     *
     * @param client reads the advisories
     */
    public FortinetReporter(FortinetPsirtClient client) {
        this(client, null);
    }

    /**
     * Creates a reporter that also asks NVD for the advisories the feed no longer lists.
     *
     * @param client reads the advisories
     * @param nvd asks NVD, or null to leave NVD out
     */
    public FortinetReporter(FortinetPsirtClient client, NvdFortiOsClient nvd) {
        this.client = client;
        this.nvd = nvd;
    }

    /**
     * Prints one row per advisory.
     *
     * @param versions the FortiOS versions to check
     * @param since only advisories released on or after this date
     * @param out where the report is written
     * @return the number of rows written
     * @throws IOException if the feed cannot be read
     */
    public int report(List<String> versions, String since, PrintStream out) throws IOException {
        out.println(HEADER);
        List<FortinetAdvisory> advisories = client.fetch(versions, since);
        for (FortinetAdvisory a : advisories) {
            out.println(String.join("\t", row(a, versions)));
        }
        int rows = advisories.size();
        if (nvd != null) {
            Set<String> seen = new LinkedHashSet<>();
            for (FortinetAdvisory a : advisories) {
                seen.addAll(a.cves());
            }
            for (List<String> row : nvdRows(versions, since, seen)) {
                out.println(String.join("\t", row));
                rows++;
            }
        }
        return rows;
    }

    /** Rows for the CVEs that NVD reports and the feed does not hold, grouped by advisory. */
    private List<List<String>> nvdRows(List<String> versions, String since, Set<String> seen)
            throws IOException {
        Map<String, Map<String, NvdFortiOsClient.Cve>> byVersion = new LinkedHashMap<>();
        Map<String, NvdFortiOsClient.Cve> all = new LinkedHashMap<>();
        for (String v : versions) {
            Map<String, NvdFortiOsClient.Cve> m = new LinkedHashMap<>();
            for (NvdFortiOsClient.Cve c : nvd.fetch(v, LocalDate.parse(since), LocalDate.now())) {
                m.put(c.id(), c);
                all.putIfAbsent(c.id(), c);
            }
            byVersion.put(v, m);
        }
        Map<String, List<NvdFortiOsClient.Cve>> groups = new LinkedHashMap<>();
        for (NvdFortiOsClient.Cve c : all.values()) {
            if (seen.contains(c.id())) {
                continue;
            }
            groups.computeIfAbsent(c.advisoryId().isEmpty() ? c.id() : c.advisoryId(),
                    k -> new ArrayList<>()).add(c);
        }
        List<List<String>> rows = new ArrayList<>();
        for (Map.Entry<String, List<NvdFortiOsClient.Cve>> g : groups.entrySet()) {
            List<NvdFortiOsClient.Cve> cves = g.getValue();
            List<String> verdicts = new ArrayList<>();
            for (String v : versions) {
                boolean hit = cves.stream().anyMatch(c -> byVersion.get(v).containsKey(c.id()));
                verdicts.add(v + ": " + (hit ? "該当" : "非該当"));
            }
            NvdFortiOsClient.Cve top = cves.stream()
                    .max(java.util.Comparator.comparingDouble(c -> score(c.cvss()))).get();
            String page = g.getKey().startsWith("FG-IR")
                    ? "https://fortiguard.fortinet.com/psirt/" + g.getKey()
                    : "https://nvd.nist.gov/vuln/detail/" + g.getKey();
            String published = cves.stream().map(NvdFortiOsClient.Cve::published).min(String::compareTo).get();
            rows.add(List.of(g.getKey(), "FortiGate",
                    String.join(" ", cves.stream().map(NvdFortiOsClient.Cve::id).toList()),
                    published, "FortiOS " + String.join(" / ", verdicts), top.severity(), top.cvss(),
                    "", top.description() + " " + page));
        }
        return rows;
    }

    private static double score(String s) {
        try {
            return Double.parseDouble(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    static List<String> row(FortinetAdvisory a, List<String> versions) {
        List<String> verdicts = new ArrayList<>();
        List<String> fixes = new ArrayList<>();
        for (String v : versions) {
            FortiOsVersionMatcher.Answer answer = a.answers().get(v);
            String word = switch (answer) {
                case AFFECTED -> "該当";
                case NOT_AFFECTED -> "非該当";
                case CHECK -> "要確認";
            };
            verdicts.add(v + ": " + word);
            if (answer != FortiOsVersionMatcher.Answer.NOT_AFFECTED
                    && a.remediations().containsKey(v)) {
                fixes.add(v + " -> " + a.remediations().get(v));
            }
        }
        return List.of(a.id(), "FortiGate", String.join(" ", a.cves()), a.published(),
                "FortiOS " + String.join(" / ", verdicts), a.severity(), a.cvss(),
                String.join("; ", fixes), a.title() + " " + a.url());
    }
}
