package com.github.oogasawa.utility.security.deps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

public class MavenDependencyListerTest {

    @Test
    void parsesPlainAndClassifierLines() {
        Set<Dependency> deps = new MavenDependencyLister().parse(List.of(
                "",
                "The following files have been resolved:",
                "   org.apache.lucene:lucene-core:jar:10.5.2:compile",
                "   io.netty:netty-transport-native-epoll:jar:linux-x86_64:4.1.100.Final:runtime -- module x (auto)"));
        assertEquals(2, deps.size());
        assertTrue(deps.contains(new Dependency("org.apache.lucene", "lucene-core", "10.5.2")));
        assertTrue(deps.contains(new Dependency("io.netty", "netty-transport-native-epoll", "4.1.100.Final")));
    }
}
