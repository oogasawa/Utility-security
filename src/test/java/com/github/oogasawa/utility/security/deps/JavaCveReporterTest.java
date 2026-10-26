package com.github.oogasawa.utility.security.deps;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("JavaCveReporter — one sheet row per advisory")
public class JavaCveReporterTest {

    @Test
    @DisplayName("The projects that share a library version are listed together on one row")
    void sheetRow_manyProjects_listsEachVersionOnceWithItsProjects() {
        Vulnerability v = new Vulnerability("GHSA-pwqr-wmgm-9rr8", List.of("CVE-2026-33870"),
                "HIGH", List.of("4.1.132.Final"), "Netty: HTTP Request Smuggling", "2026-03-26");
        JavaCveReporter.SheetRow row = new JavaCveReporter.SheetRow(v, v.summary());

        row.add(new Dependency("io.netty", "netty-codec-http", "4.1.127.Final"), "k8s-pups");
        row.add(new Dependency("io.netty", "netty-codec-http", "4.1.118.Final"),
                "toolkit-launcher");
        row.add(new Dependency("io.netty", "netty-codec-http", "4.1.127.Final"), "code-raptor");

        assertEquals("io.netty:netty-codec-http 4.1.118.Final (toolkit-launcher) / "
                + "4.1.127.Final (code-raptor, k8s-pups)", row.target());
        assertEquals("GHSA-pwqr-wmgm-9rr8\tJava\tCVE-2026-33870\t2026-03-26\t" + row.target()
                + "\tHIGH\t\t4.1.132.Final\tNetty: HTTP Request Smuggling", row.toTsv());
    }
}
