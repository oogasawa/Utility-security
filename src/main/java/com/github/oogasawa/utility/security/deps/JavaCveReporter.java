package com.github.oogasawa.utility.security.deps;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Writes a TSV report of the known vulnerabilities in the dependencies of Maven projects.
 */
public class JavaCveReporter {

    private static final Logger logger = LoggerFactory.getLogger(JavaCveReporter.class);

    /** Header line of the report. */
    public static final String HEADER =
            "project\tdependency\tversion\tvulnerability\tcve\tseverity\tfixed\tsummary";

    /** Header line of the report in the columns of the patch history sheet. */
    public static final String SHEET_HEADER =
            "id\tcategory\tcve\tpublished_date\ttarget\tseverity\tcvss\tfixed\tsummary";

    private final MavenDependencyLister lister;
    private final OsvClient osv;

    /**
     * Creates a reporter.
     *
     * @param lister resolves the dependencies of a project
     * @param osv looks up vulnerabilities
     */
    public JavaCveReporter(MavenDependencyLister lister, OsvClient osv) {
        this.lister = lister;
        this.osv = osv;
    }

    /**
     * Lists the child directories of a works directory that contain a {@code pom.xml}.
     *
     * @param worksDir the directory to scan
     * @return the project directories, sorted by name
     * @throws IOException if the directory cannot be read
     */
    public static List<Path> findProjects(Path worksDir) throws IOException {
        try (Stream<Path> s = Files.list(worksDir)) {
            return s.filter(p -> Files.isRegularFile(p.resolve("pom.xml"))).sorted().toList();
        }
    }

    /**
     * Checks each project and prints one TSV row per affected dependency and vulnerability.
     * A project whose dependencies cannot be listed is logged and skipped.
     *
     * @param projects project directories
     * @param out where the report is written
     * @return the number of vulnerability rows written
     * @throws IOException if OSV cannot be reached
     */
    public int report(List<Path> projects, PrintStream out) throws IOException {
        return report(projects, out, false);
    }

    /**
     * Checks each project and prints one TSV row per affected dependency and vulnerability.
     *
     * @param projects project directories
     * @param out where the report is written
     * @param sheetFormat true to write the columns of the patch history sheet for CVEs other than
     *        Ubuntu's, false for the columns of the stand-alone report
     * @return the number of vulnerability rows written
     * @throws IOException if OSV cannot be reached
     */
    public int report(List<Path> projects, PrintStream out, boolean sheetFormat)
            throws IOException {
        out.println(sheetFormat ? SHEET_HEADER : HEADER);
        int rows = 0;
        Map<String, SheetRow> sheetRows = new TreeMap<>();
        for (Path project : projects) {
            Set<Dependency> deps;
            try {
                deps = lister.list(project);
            } catch (IOException e) {
                logger.error("Skipped {}: {}", project, e.getMessage());
                continue;
            }
            logger.info("{}: {} dependencies", project.getFileName(), deps.size());
            Map<Dependency, List<Vulnerability>> found = osv.query(new ArrayList<>(deps));
            for (Map.Entry<Dependency, List<Vulnerability>> e : found.entrySet()) {
                for (Vulnerability v : e.getValue()) {
                    String summary = v.summary().replaceAll("[\\t\\r\\n]+", " ");
                    if (sheetFormat) {
                        sheetRows.computeIfAbsent(v.id(), id -> new SheetRow(v, summary))
                                .add(e.getKey(), project.getFileName().toString());
                        continue;
                    }
                    out.println(String.join("\t",
                            project.getFileName().toString(),
                            e.getKey().osvName(),
                            e.getKey().version(),
                            v.id(),
                            String.join(",", v.cves()),
                            v.severity(),
                            String.join(",", v.fixedVersions()),
                            summary));
                    rows++;
                }
            }
        }
        for (SheetRow row : sheetRows.values()) {
            out.println(row.toTsv());
            rows++;
        }
        return rows;
    }

    /**
     * One row of the patch history sheet: one advisory, with every project it affects.
     *
     * <p>
     * Many projects share a library, so one advisory affects many of them at once. A row per
     * project repeated the same advisory dozens of times in the sheet, differing only in the
     * project name at the end of the target. The target lists each affected library version
     * once, followed by the projects that use it.
     * </p>
     */
    static final class SheetRow {

        private final Vulnerability vulnerability;
        private final String summary;
        private final Map<String, Map<String, Set<String>>> projectsByVersionByLibrary =
                new TreeMap<>();

        SheetRow(Vulnerability vulnerability, String summary) {
            this.vulnerability = vulnerability;
            this.summary = summary;
        }

        void add(Dependency dependency, String project) {
            this.projectsByVersionByLibrary
                    .computeIfAbsent(dependency.osvName(), key -> new TreeMap<>())
                    .computeIfAbsent(dependency.version(), key -> new TreeSet<>())
                    .add(project);
        }

        /**
         * Writes the target, as in
         * {@code io.netty:netty-codec-http 4.1.118.Final (toolkit-launcher) / 4.1.124.Final (a, b)}.
         */
        String target() {
            List<String> libraries = new ArrayList<>();
            for (Map.Entry<String, Map<String, Set<String>>> library
                    : this.projectsByVersionByLibrary.entrySet()) {
                List<String> versions = new ArrayList<>();
                for (Map.Entry<String, Set<String>> version : library.getValue().entrySet()) {
                    versions.add(version.getKey() + " (" + String.join(", ", version.getValue())
                            + ")");
                }
                libraries.add(library.getKey() + " " + String.join(" / ", versions));
            }
            return String.join("; ", libraries);
        }

        String toTsv() {
            Vulnerability v = this.vulnerability;
            return String.join("\t", v.id(), "Java", String.join(" ", v.cves()), v.published(),
                    target(), v.severity(), "", String.join(",", v.fixedVersions()),
                    this.summary);
        }
    }
}
