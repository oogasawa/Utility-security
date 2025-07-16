package com.github.oogasawa.utility.security.log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A utility class that processes and renames system log files by
 * appending server name and rotation date, then copies them to a destination directory.
 */
public class LogRenamer {

    /** Logger instance for reporting errors and progress. */
    private static final Logger logger = LoggerFactory.getLogger(LogRenamer.class);

    /**
     * Starts the log renaming process for a given server.
     *
     * <p>This method verifies the source directory, creates the destination directory if needed,
     * and processes log files that match known patterns. Each matched log file will be copied
     * to the destination directory with a modified file name that includes the server name and date.</p>
     *
     * @param serverName The server name to append to renamed log files
     * @param sourceDir  The root directory to scan for log files
     * @param destDir    The destination directory to write renamed files
     */
    public void rename(String serverName, Path sourceDir, Path destDir) {
        try {
            if (!Files.isDirectory(sourceDir)) {
                System.err.println("Source directory does not exist: " + sourceDir);
                System.exit(2);
            }

            Files.createDirectories(destDir);

            LogFileProcessor processor = new LogFileProcessor(serverName, destDir);
            Files.walkFileTree(sourceDir, processor);

        } catch (IOException e) {
            logger.error("IOException occurred during log file processing.", e);
        }
    }

    /**
     * Retrieves the host name of the current machine.
     *
     * <p>This method uses {@link InetAddress#getLocalHost()} to obtain the system's host name.
     * If the host name cannot be determined, it logs an error and returns {@code null}.</p>
     *
     * @return The host name as a {@code String}, or {@code null} if not resolvable
     */
    public static String hostName() {
        String hostname = null;
        try {
            hostname = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            logger.error("Cannot determine host name.", e);
        }
        return hostname;
    }
}

