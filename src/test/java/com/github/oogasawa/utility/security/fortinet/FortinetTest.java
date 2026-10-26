package com.github.oogasawa.utility.security.fortinet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.oogasawa.utility.security.fortinet.FortiOsVersionMatcher.Answer;

public class FortinetTest {

    private static String resource(String name) throws Exception {
        return Files.readString(Path.of("src/test/resources/fortinet/" + name),
                StandardCharsets.UTF_8);
    }

    @Test
    void matcherHandlesTheThreeForms() {
        assertEquals(Answer.AFFECTED,
                FortiOsVersionMatcher.check("7.4.6", List.of("FortiOS 7.4 all versions")));
        assertEquals(Answer.AFFECTED,
                FortiOsVersionMatcher.check("7.4.6", List.of("FortiOS >=7.4.0|<=7.4.8")));
        assertEquals(Answer.NOT_AFFECTED,
                FortiOsVersionMatcher.check("7.4.11", List.of("FortiOS >=7.4.0|<=7.4.8")));
        assertEquals(Answer.AFFECTED,
                FortiOsVersionMatcher.check("7.4.10", List.of("FortiOS >=7.4.0|<=7.4.11")));
        assertEquals(Answer.NOT_AFFECTED,
                FortiOsVersionMatcher.check("7.4.6", List.of("FortiOS 7.6.0", "FortiOS 7.2 all versions")));
        assertEquals(Answer.AFFECTED, FortiOsVersionMatcher.check("7.6.0", List.of("FortiOS 7.6.0")));
        assertEquals(Answer.CHECK,
                FortiOsVersionMatcher.check("7.4.6", List.of("FortiOS something odd")));
        assertEquals(Answer.NOT_AFFECTED, FortiOsVersionMatcher.check("7.4.6", List.of()));
    }

    @Test
    void sevenFourPointOneIsNotInSevenFourPointOneOne() {
        // "7.4 all versions" must not match 7.40.x
        assertEquals(Answer.NOT_AFFECTED,
                FortiOsVersionMatcher.check("7.40.1", List.of("FortiOS 7.4 all versions")));
    }

    @Test
    void parsesAllVersionsAdvisory() throws Exception {
        var node = new ObjectMapper().readTree(resource("all-versions-7.4.json"));
        FortinetAdvisory a = FortinetPsirtClient.parse(node, List.of("7.4.6", "7.4.11"), "https://x/FG-IR-26-182");
        assertNotNull(a);
        assertEquals("FG-IR-26-182", a.id());
        assertEquals("2026-10-13", a.published());
        assertEquals(List.of("CVE-2026-106175"), a.cves());
        assertEquals("LOW", a.severity());
        assertEquals(Answer.AFFECTED, a.answers().get("7.4.6"));
        assertEquals(Answer.AFFECTED, a.answers().get("7.4.11"));
        assertEquals("FortiOS 7.4: Migrate to a fixed release", a.remediations().get("7.4.6"));
    }

    @Test
    void rangeAdvisoryAffectsOnlyTheOlderVersion() throws Exception {
        var node = new ObjectMapper().readTree(resource("range-7.4.0-7.4.8.json"));
        FortinetAdvisory a = FortinetPsirtClient.parse(node, List.of("7.4.6", "7.4.11"), "u");
        assertNotNull(a);
        assertEquals(Answer.AFFECTED, a.answers().get("7.4.6"));
        assertEquals(Answer.NOT_AFFECTED, a.answers().get("7.4.11"));
    }

    @Test
    void reportKeepsOnlyAdvisoriesThatConcernAVersionAndWritesTsv() throws Exception {
        String feed = """
                <?xml version="1.0"?>
                <rss xmlns:csaf="https://fortiguard.fortinet.com/rss/ns/csaf" version="2.0"><channel>
                <item><title>a</title><link>https://p/FG-IR-26-182</link>
                  <csaf:link>https://c/a.json</csaf:link></item>
                <item><title>b</title><link>https://p/FG-IR-20-005</link></item>
                </channel></rss>
                """;
        TextFetcher fake = url -> {
            try {
                if (url.equals(FortinetPsirtClient.FEED_URL)) {
                    return feed;
                }
                return resource("all-versions-7.4.json");
            } catch (Exception e) {
                throw new java.io.IOException(e);
            }
        };
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int rows = new FortinetReporter(new FortinetPsirtClient(fake)).report(
                List.of("7.4.6", "7.4.11"), "2026-01-01",
                new PrintStream(buf, true, StandardCharsets.UTF_8));
        String[] lines = buf.toString(StandardCharsets.UTF_8).split("\n");
        assertEquals(1, rows);
        assertEquals(FortinetReporter.HEADER, lines[0]);
        String[] c = lines[1].split("\t", -1);
        assertEquals(9, c.length);
        assertEquals("FG-IR-26-182", c[0]);
        assertEquals("FortiGate", c[1]);
        assertTrue(c[4].contains("7.4.6: 該当") && c[4].contains("7.4.11: 該当"));
    }

    @Test
    void nvdFillsInAdvisoriesTheFeedNoLongerHolds() throws Exception {
        String feed = "<?xml version=\"1.0\"?><rss version=\"2.0\"><channel></channel></rss>";
        String nvdJson = resource("nvd-fortios-7.4.6.json");
        TextFetcher fake = url -> {
            try {
                if (url.equals(FortinetPsirtClient.FEED_URL)) {
                    return feed;
                }
                return url.contains("fortios:7.4.6") ? nvdJson : "{\"vulnerabilities\":[]}";
            } catch (Exception e) {
                throw new java.io.IOException(e);
            }
        };
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int rows = new FortinetReporter(new FortinetPsirtClient(fake), new NvdFortiOsClient(fake))
                .report(List.of("7.4.6", "7.4.11"), "2026-01-01",
                        new PrintStream(buf, true, StandardCharsets.UTF_8));
        String out = buf.toString(StandardCharsets.UTF_8);
        assertEquals(2, rows);
        assertTrue(out.contains("FortiOS 7.4.6: 該当 / 7.4.11: 非該当"), out);
        assertTrue(out.contains("FG-IR-"), out);
    }
}
