package com.github.oogasawa.utility.security.deps;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Finds the known vulnerabilities of Maven artifacts through the OSV.dev API.
 *
 * <p>
 * One batch query returns only the vulnerability ids for each artifact. The severity, the CVE
 * aliases and the fixed versions are read from the record of each id, which is fetched once even
 * when many artifacts share it.
 * </p>
 */
public class OsvClient {

    private static final String BASE = "https://api.osv.dev/v1";
    private static final int BATCH_SIZE = 500;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final OsvTransport transport;
    private final Map<String, JsonNode> records = new HashMap<>();

    /** Creates a client that talks to api.osv.dev. */
    public OsvClient() {
        this(new HttpOsvTransport());
    }

    /**
     * Creates a client on the given transport.
     *
     * @param transport sends the requests
     */
    public OsvClient(OsvTransport transport) {
        this.transport = transport;
    }

    /**
     * Looks up the vulnerabilities that affect each dependency.
     *
     * @param deps the dependencies to check
     * @return the vulnerabilities per dependency; a dependency with none is absent
     * @throws IOException if OSV cannot be reached or answers with an error
     */
    public Map<Dependency, List<Vulnerability>> query(List<Dependency> deps) throws IOException {
        Map<Dependency, List<Vulnerability>> result = new LinkedHashMap<>();
        for (int from = 0; from < deps.size(); from += BATCH_SIZE) {
            List<Dependency> chunk = deps.subList(from, Math.min(from + BATCH_SIZE, deps.size()));
            ObjectNode body = MAPPER.createObjectNode();
            ArrayNode queries = body.putArray("queries");
            for (Dependency d : chunk) {
                ObjectNode q = queries.addObject();
                ObjectNode pkg = q.putObject("package");
                pkg.put("ecosystem", "Maven");
                pkg.put("name", d.osvName());
                q.put("version", d.version());
            }
            JsonNode res = MAPPER.readTree(transport.post(BASE + "/querybatch",
                    MAPPER.writeValueAsString(body)));
            JsonNode results = res.path("results");
            if (results.size() != chunk.size()) {
                throw new IOException("OSV returned " + results.size() + " results for "
                        + chunk.size() + " queries");
            }
            for (int i = 0; i < chunk.size(); i++) {
                Dependency d = chunk.get(i);
                for (JsonNode v : results.get(i).path("vulns")) {
                    result.computeIfAbsent(d, k -> new ArrayList<>())
                            .add(toVulnerability(d, record(v.path("id").asText())));
                }
            }
        }
        return result;
    }

    private JsonNode record(String id) throws IOException {
        JsonNode cached = records.get(id);
        if (cached != null) {
            return cached;
        }
        String json = transport.get(BASE + "/vulns/" + id);
        JsonNode node = json == null ? MAPPER.createObjectNode().put("id", id) : MAPPER.readTree(json);
        records.put(id, node);
        return node;
    }

    private static String publishedDate(String timestamp) {
        return timestamp.length() >= 10 ? timestamp.substring(0, 10) : timestamp;
    }

    private static Vulnerability toVulnerability(Dependency dep, JsonNode r) {
        List<String> cves = new ArrayList<>();
        for (JsonNode a : r.path("aliases")) {
            if (a.asText().startsWith("CVE-")) {
                cves.add(a.asText());
            }
        }
        if (r.path("id").asText().startsWith("CVE-") && !cves.contains(r.path("id").asText())) {
            cves.add(r.path("id").asText());
        }
        String severity = r.path("database_specific").path("severity").asText("");
        if (severity.isEmpty()) {
            severity = "Unknown";
        }
        List<String> fixed = new ArrayList<>();
        for (JsonNode aff : r.path("affected")) {
            if (!dep.osvName().equals(aff.path("package").path("name").asText())) {
                continue;
            }
            for (JsonNode range : aff.path("ranges")) {
                for (JsonNode ev : range.path("events")) {
                    if (ev.has("fixed") && !fixed.contains(ev.get("fixed").asText())) {
                        fixed.add(ev.get("fixed").asText());
                    }
                }
            }
        }
        return new Vulnerability(r.path("id").asText(), cves, severity, fixed,
                r.path("summary").asText(""), publishedDate(r.path("published").asText("")));
    }
}
