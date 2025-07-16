package com.github.oogasawa.utility.security.log;

import org.junit.jupiter.api.*;
import java.nio.file.*;
import java.util.*;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LogFileProcessorIntegrationTest {

    private static Path sourceDir;
    private static Path destDir;
    private static final String serverName = "testServer";

    @BeforeAll
    static void setup() throws IOException {
        sourceDir = Files.createTempDirectory("log-test-src");
        destDir = Files.createTempDirectory("log-test-dest");
        SimulatedLogDataPopulator.populate(sourceDir);
    }

    @Test
    void testAllExpectedFilesAreRenamedCorrectly() throws IOException {
        LogFileProcessor processor = new LogFileProcessor(serverName, destDir);
        Files.walkFileTree(sourceDir, processor);

        List<String> expectedFileNames = new ArrayList<>();
        List<String> destFileNames = new ArrayList<>();

        Files.walk(sourceDir)
                .filter(Files::isRegularFile)
                .forEach(path -> {
                    String fileName = path.getFileName().toString();
                    if (LogFileFilter.isTarget(fileName)) {
                        // Skip files ending with .log, .log.1, or containing -nigscHP2
                        if (fileName.matches(".*(\\.log(\\.\\d+)?|-nigscHP2)(\\.gz)?$")) {
                            return;
                        }
                        String date = LogFileNameHelper.extractDateFromFileName(fileName);
                        if (date == null) {
                            try {
                                date = LogFileNameHelper.getDateFromTimestamp(Files.getLastModifiedTime(path));
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        }
                        expectedFileNames.add(LogFileNameHelper.buildNewFileName(fileName, date, serverName));
                    }
                });

        Files.walk(destDir)
                .filter(Files::isRegularFile)
                .forEach(path -> destFileNames.add(path.getFileName().toString()));

        Collections.sort(expectedFileNames);
        Collections.sort(destFileNames);

        System.out.println("=== Expected Renamed Files ===");
        expectedFileNames.forEach(f -> System.out.println("  " + f));

        System.out.println("=== Actual Copied Files ===");
        destFileNames.forEach(f -> System.out.println("  " + f));

        assertEquals(expectedFileNames, destFileNames, "Mismatch between expected and actual renamed files.");
    }

    @AfterAll
    static void cleanup() throws IOException {
        deleteRecursively(sourceDir);
        deleteRecursively(destDir);
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (!Files.exists(path)) return;
        Files.walk(path)
                .sorted(Comparator.reverseOrder())
                .forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (IOException e) {
                        System.err.println("Failed to delete: " + p);
                    }
                });
    }
}
