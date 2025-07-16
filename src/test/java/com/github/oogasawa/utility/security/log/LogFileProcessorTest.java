package com.github.oogasawa.utility.security.log;

import org.junit.jupiter.api.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link LogFileProcessor}.
 *
 * <p>This test verifies that log files are properly filtered, renamed, and copied
 * to a destination directory based on server name and rotation date logic.</p>
 */
class LogFileProcessorTest {

    private Path sourceDir;
    private Path destDir;
    private final String serverName = "testServer";

    /**
     * Sets up temporary directories and test files before each test.
     *
     * @throws IOException if temp file or directory creation fails
     */
    @BeforeEach
    void setUp() throws IOException {
        sourceDir = Files.createTempDirectory("logSource");
        destDir = Files.createTempDirectory("logDest");

        // Create a mix of target and non-target files
        Files.write(sourceDir.resolve("auth.log"), List.of("dummy log"));
        Files.write(sourceDir.resolve("auth.log-20250615"), List.of("dummy rotated log"));
        Files.write(sourceDir.resolve("README"), List.of("this should be ignored"));
        Files.write(sourceDir.resolve("access.log-20250610.gz"), new byte[]{0x1f, (byte) 0x8b});  // gzipped dummy
    }

    /**
     * Cleans up the temporary files and directories after each test.
     *
     * @throws IOException if cleanup fails
     */
    @AfterEach
    void tearDown() throws IOException {
        Files.walk(destDir)
                .sorted((a, b) -> b.compareTo(a))
                .forEach(path -> path.toFile().delete());

        Files.walk(sourceDir)
                .sorted((a, b) -> b.compareTo(a))
                .forEach(path -> path.toFile().delete());
    }

    /**
     * Tests that only target log files are renamed and copied to the destination directory.
     *
     * <p>The test verifies:
     * <ul>
     *   <li>Current logs like {@code auth.log} are skipped entirely.</li>
     *   <li>Files like {@code auth.log-20250615} already containing a date are not duplicated.</li>
     *   <li>Non-log files like {@code README} are ignored.</li>
     * </ul>
     *
     * @throws IOException if file operations fail
     */
    @Test
    void testLogFileProcessing() throws IOException {
        LogFileProcessor processor = new LogFileProcessor(serverName, destDir);
        Files.walkFileTree(sourceDir, processor);

        List<String> copiedFiles = Files.list(destDir).map(p -> p.getFileName().toString())
                .collect(Collectors.toList());

        assertEquals(2, copiedFiles.size(), "Only 2 log files with dates should be copied");

        // auth.log → skipped
        assertTrue(copiedFiles.stream().noneMatch(name -> name.startsWith("auth.log_")),
                "auth.log without date should be skipped");

        // auth.log-20250615 → valid
        assertTrue(copiedFiles.contains("auth.log-20250615_testServer"),
                "auth.log-20250615 should be renamed");

        // access.log-20250610.gz → valid
        assertTrue(copiedFiles.contains("access.log-20250610.gz_testServer"),
                "access.log-20250610.gz should be renamed");

        // README should still be ignored
        assertTrue(copiedFiles.stream().noneMatch(name -> name.contains("README")),
                "README should not be processed");
    }

}
