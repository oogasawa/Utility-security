package com.github.oogasawa.utility.security.fortinet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Reads the FortiGuard PSIRT advisory feed and the CSAF file of each advisory, and keeps the
 * advisories that list FortiOS versions of interest as affected.
 *
 * <p>
 * The feed holds the latest fifty advisories, about a year. An advisory is looked at once per
 * run; running this every week therefore sees each advisory before it leaves the feed.
 * </p>
 */
public class FortinetPsirtClient {

    private static final Logger logger = LoggerFactory.getLogger(FortinetPsirtClient.class);

    /** The advisory feed. */
    public static final String FEED_URL = "https://www.fortiguard.com/rss/ir.xml";

    private static final String CSAF_NS = "https://fortiguard.fortinet.com/rss/ns/csaf";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TextFetcher fetcher;

    /** Creates a client that reads fortiguard.com. */
    public FortinetPsirtClient() {
        this(new HttpTextFetcher());
    }

    /**
     * Creates a client on the given fetcher.
     *
     * @param fetcher fetches the feed and the CSAF files
     */
    public FortinetPsirtClient(TextFetcher fetcher) {
        this.fetcher = fetcher;
    }

    /**
     * Fetches the advisories that concern a FortiOS version.
     *
     * @param versions the FortiOS versions to check, such as {@code 7.4.6}
     * @param since only advisories released on or after this date, as {@code yyyy-MM-dd}
     * @return the advisories, newest first as the feed lists them
     * @throws IOException if the feed cannot be read
     */
    public List<FortinetAdvisory> fetch(List<String> versions, String since) throws IOException {
        List<String[]> entries = readFeed();
        logger.info("The feed lists {} advisories", entries.size());

        List<FortinetAdvisory> result = new ArrayList<>();
        for (String[] e : entries) {
            String csafUrl = e[0];
            String pageUrl = e[1];
            if (csafUrl.isEmpty()) {
                logger.info("{} has no CSAF file; skipped", pageUrl);
                continue;
            }
            JsonNode csaf;
            try {
                csaf = MAPPER.readTree(fetcher.get(csafUrl));
            } catch (IOException ex) {
                logger.error("Skipped {}: {}", csafUrl, ex.getMessage());
                continue;
            }
            FortinetAdvisory a = parse(csaf, versions, pageUrl);
            if (a != null && a.published().compareTo(since) >= 0 && a.concernsAnyVersion()) {
                result.add(a);
            }
        }
        return result;
    }

    /** Returns {csafUrl, pageUrl} per item of the feed. */
    private List<String[]> readFeed() throws IOException {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            var doc = f.newDocumentBuilder().parse(new ByteArrayInputStream(
                    fetcher.get(FEED_URL).getBytes(StandardCharsets.UTF_8)));
            NodeList items = doc.getElementsByTagName("item");
            List<String[]> out = new ArrayList<>();
            for (int i = 0; i < items.getLength(); i++) {
                Element item = (Element) items.item(i);
                NodeList csaf = item.getElementsByTagNameNS(CSAF_NS, "link");
                NodeList page = item.getElementsByTagName("link");
                out.add(new String[] {
                        csaf.getLength() > 0 ? csaf.item(0).getTextContent().trim() : "",
                        page.getLength() > 0 ? page.item(0).getTextContent().trim() : ""});
            }
            return out;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Cannot parse the advisory feed: " + e.getMessage(), e);
        }
    }

    /**
     * Reads one CSAF file.
     *
     * @return the advisory, or null when FortiOS is not listed as affected in it
     */
    static FortinetAdvisory parse(JsonNode csaf, List<String> versions, String pageUrl) {
        Set<String> affected = new LinkedHashSet<>();
        Set<String> cves = new LinkedHashSet<>();
        String cvss = "";
        String severity = "";
        String title = "";
        Map<String, String> remediations = new LinkedHashMap<>();
        for (JsonNode v : csaf.path("vulnerabilities")) {
            for (JsonNode p : v.path("product_status").path("known_affected")) {
                if (p.asText().startsWith("FortiOS ")) {
                    affected.add(p.asText());
                }
            }
            if (v.has("cve")) {
                cves.add(v.get("cve").asText());
            }
            if (title.isEmpty()) {
                title = v.path("notes").path(0).path("text").asText("").strip();
            }
            for (JsonNode s : v.path("scores")) {
                JsonNode c = s.path("cvss_v3");
                if (!c.isMissingNode() && cvss.isEmpty()) {
                    cvss = c.path("baseScore").asText("");
                    severity = c.path("baseSeverity").asText("");
                }
            }
            for (JsonNode r : v.path("remediations")) {
                String details = r.path("details").asText("");
                for (String version : versions) {
                    String branch = branchOf(version);
                    for (String line : details.split("\n")) {
                        if (line.startsWith("FortiOS " + branch + ":")) {
                            remediations.putIfAbsent(version, line.strip());
                        }
                    }
                }
            }
        }
        if (affected.isEmpty()) {
            return null;
        }
        String id = csaf.path("document").path("tracking").path("id").asText("");
        String released = csaf.path("document").path("tracking").path("initial_release_date")
                .asText("");
        String published = released.length() >= 10 ? released.substring(0, 10) : released;
        if (title.isEmpty()) {
            title = csaf.path("vulnerabilities").path(0).path("title").asText("");
        }
        Map<String, FortiOsVersionMatcher.Answer> answers = new LinkedHashMap<>();
        for (String version : versions) {
            answers.put(version, FortiOsVersionMatcher.check(version, new ArrayList<>(affected)));
        }
        return new FortinetAdvisory(id, title.replaceAll("\\s+", " "), published,
                new ArrayList<>(cves), cvss, severity, answers, remediations, pageUrl);
    }

    private static String branchOf(String version) {
        int second = version.indexOf('.', version.indexOf('.') + 1);
        return second < 0 ? version : version.substring(0, second);
    }
}
