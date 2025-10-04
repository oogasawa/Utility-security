package com.github.oogasawa.utility.security.log;

import org.junit.jupiter.api.*;
import java.nio.file.*;
import java.util.*;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Integration tests for {@link LogFileProcessor} verifying end-to-end log renaming behavior.
 */
public class LogFileProcessorIntegrationTest {

    private static Path sourceDir;
    private static Path destDir;
    private static final String serverName = "testServer";

    /**
     * Creates temporary source and destination directories populated with simulated log data.
     */
    @BeforeAll
    static void setup() throws IOException {
        sourceDir = Files.createTempDirectory("log-test-src");
        destDir = Files.createTempDirectory("log-test-dest");
        SimulatedLogDataPopulator.populate(sourceDir);
    }

    /**
     * Ensures that every eligible log file is copied to the destination directory with the expected
     * normalized file name.
     */
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
                        String date = LogFileNameHelper.extractDateFromFileName(fileName);
                        // Skip files without a date in the name
                        if (date != null) {
                            expectedFileNames.add(LogFileNameHelper.buildNewFileName(fileName, date, serverName));
                        }
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

    /**
     * Removes the temporary directories and files created for the integration test.
     */
    @AfterAll
    static void cleanup() throws IOException {
        deleteRecursively(sourceDir);
        deleteRecursively(destDir);
    }

    /**
     * Deletes a directory tree, ignoring failures to remove individual files.
     *
     * @param path root directory to delete recursively
     * @throws IOException if the file walk cannot be initiated
     */
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
