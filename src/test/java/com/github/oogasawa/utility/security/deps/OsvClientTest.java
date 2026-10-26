package com.github.oogasawa.utility.security.deps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;

public class OsvClientTest {

    private static final Dependency VULN = new Dependency("org.apache.tomcat.embed", "tomcat-embed-core", "10.1.0");
    private static final Dependency CLEAN = new Dependency("org.jsoup", "jsoup", "1.23.2");

    private static final String RECORD = """
            {"id":"GHSA-xxxx","aliases":["CVE-2099-0001"],"summary":"Bad\\tthing",
             "database_specific":{"severity":"HIGH"},
             "affected":[{"package":{"ecosystem":"Maven","name":"org.apache.tomcat.embed:tomcat-embed-core"},
               "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"10.0.0"},{"fixed":"10.1.5"}]}]}]}
            """;

    private static final OsvTransport FAKE = new OsvTransport() {
        public String post(String url, String json) {
            return "{\"results\":[{\"vulns\":[{\"id\":\"GHSA-xxxx\"}]},{}]}";
        }
        public String get(String url) {
            return url.endsWith("/GHSA-xxxx") ? RECORD : null;
        }
    };

    @Test
    void readsSeverityCveAndFixedVersion() throws Exception {
        Map<Dependency, List<Vulnerability>> r = new OsvClient(FAKE).query(List.of(VULN, CLEAN));
        assertEquals(1, r.size());
        assertFalse(r.containsKey(CLEAN));
        Vulnerability v = r.get(VULN).get(0);
        assertEquals("GHSA-xxxx", v.id());
        assertEquals(List.of("CVE-2099-0001"), v.cves());
        assertEquals("HIGH", v.severity());
        assertEquals(List.of("10.1.5"), v.fixedVersions());
    }

    @Test
    void reporterWritesOneTsvRowPerVulnerability() throws Exception {
        MavenDependencyLister lister = new MavenDependencyLister() {
            @Override
            public Set<Dependency> list(Path dir) {
                Set<Dependency> s = new TreeSet<>(java.util.Comparator.comparing(Dependency::toString));
                s.add(VULN);
                s.add(CLEAN);
                return s;
            }
        };
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int rows = new JavaCveReporter(lister, new OsvClient(FAKE))
                .report(List.of(Path.of("/tmp/proj")), new PrintStream(buf, true, StandardCharsets.UTF_8));
        String[] lines = buf.toString(StandardCharsets.UTF_8).split("\n");
        assertEquals(1, rows);
        assertEquals(JavaCveReporter.HEADER, lines[0]);
        assertEquals("proj\torg.apache.tomcat.embed:tomcat-embed-core\t10.1.0\tGHSA-xxxx\tCVE-2099-0001\tHIGH\t10.1.5\tBad thing",
                lines[1]);
    }
}
