package com.github.oogasawa.utility.security.deps;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

/**
 * Lists the compile and runtime dependencies of a Maven project, including transitive ones.
 *
 * <p>
 * The list comes from {@code mvn dependency:list}, so it holds the versions Maven actually
 * resolves after mediation, not the versions written in {@code pom.xml}. For a multi-module
 * project the modules are merged into one set.
 * </p>
 */
public class MavenDependencyLister {

    private static final long TIMEOUT_MINUTES = 10;

    /**
     * Runs Maven in the project directory and returns the resolved dependencies.
     *
     * @param projectDir a directory that contains a {@code pom.xml}
     * @return the dependencies, sorted by coordinates
     * @throws IOException if Maven cannot be run or exits with an error
     */
    public Set<Dependency> list(Path projectDir) throws IOException {
        Path out = Files.createTempFile("dependency-list", ".txt");
        try {
            Files.deleteIfExists(out);
            ProcessBuilder pb = new ProcessBuilder(System.getenv().getOrDefault("MVN_BIN", "mvn"), "-B", "-q",
                    "dependency:list", "-DincludeScope=runtime",
                    "-DappendOutput=true", "-DoutputFile=" + out.toAbsolutePath());
            pb.directory(projectDir.toFile());
            pb.redirectErrorStream(true);
            pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
            Process p = pb.start();
            if (!p.waitFor(TIMEOUT_MINUTES, TimeUnit.MINUTES)) {
                p.destroyForcibly();
                throw new IOException("mvn dependency:list timed out in " + projectDir);
            }
            if (p.exitValue() != 0) {
                throw new IOException("mvn dependency:list failed in " + projectDir
                        + " (exit " + p.exitValue() + ")");
            }
            if (!Files.exists(out)) {
                return new TreeSet<>(java.util.Comparator.comparing(Dependency::toString));
            }
            return parse(Files.readAllLines(out, StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while running mvn in " + projectDir, e);
        } finally {
            Files.deleteIfExists(out);
        }
    }

    /**
     * Parses the lines written by {@code dependency:list}.
     *
     * <p>
     * A line is {@code group:artifact:type:version:scope}, or
     * {@code group:artifact:type:classifier:version:scope} when the artifact has a classifier.
     * Other lines, such as the heading, are ignored.
     * </p>
     *
     * @param lines the lines of the output file
     * @return the dependencies, sorted by coordinates
     */
    public Set<Dependency> parse(List<String> lines) {
        Set<Dependency> result = new TreeSet<>(java.util.Comparator.comparing(Dependency::toString));
        for (String raw : lines) {
            String line = raw.strip();
            int space = line.indexOf(' ');
            if (space >= 0) {
                line = line.substring(0, space);
            }
            String[] f = line.split(":");
            if (f.length == 5) {
                result.add(new Dependency(f[0], f[1], f[3]));
            } else if (f.length == 6) {
                result.add(new Dependency(f[0], f[1], f[4]));
            }
        }
        return result;
    }
}
