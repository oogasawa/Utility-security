package com.github.oogasawa.utility.security.log;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A file visitor that traverses a directory tree and processes log files.
 * 
 * <p>For each file that matches known log filename patterns, this processor extracts
 * a date (from the filename or file metadata), appends the server name and date
 * to the file name, and copies it to the specified destination directory.</p>
 */
public class LogFileProcessor extends SimpleFileVisitor<Path> {

    private static final Logger logger = LoggerFactory.getLogger(LogFileProcessor.class);
    
    /** The server name to append to the file names. */
    private final String serverName;


    /** The destination directory where renamed files are copied. */
    private final Path destDir;

    /**
     * Constructs a new LogFileProcessor instance.
     *
     * @param serverName the name of the server, used in renamed files
     * @param destDir the destination directory to copy renamed files to
     */
    LogFileProcessor(String serverName, Path destDir) {
        this.serverName = serverName;
        this.destDir = destDir;
    }

    /**
     * Processes a file during the file tree walk.
     *
     * <p>If the file matches known log patterns, it is copied to the destination
     * directory with a new name containing the server name and rotation date.</p>
     *
     * @param file the path to the file being visited
     * @param attrs file attributes including last modified time
     * @return {@link FileVisitResult#CONTINUE} to continue visiting files
     * @throws IOException if an I/O error occurs while copying the file
     */
    @Override
    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
        if (!Files.isRegularFile(file))
            return FileVisitResult.CONTINUE;

        String fileName = file.getFileName().toString();
        String renamedFile = getRenamedFileIfTarget(fileName, attrs.lastModifiedTime(), serverName);

        
        if (renamedFile != null) {
            Path destFile = destDir.resolve(renamedFile);
            Files.copy(file, destFile, StandardCopyOption.REPLACE_EXISTING);
            logger.info("Copied: {} → {}", file, destFile);
        }

        return FileVisitResult.CONTINUE;
    }
 

    /**
     * Determines whether a given log file should be renamed and returns the new name if applicable.
     *
     * <p>This method checks if the file name matches known log file patterns. If so, it attempts to
     * extract a rotation date (in yyyyMMdd format) from the file name. If no date is found in the
     * name, it falls back to using the file's last modified timestamp. If a valid date is available,
     * the method generates a new file name by appending the server name and date to the original name,
     * following a specific naming convention. Files without a date in the name are ignored and return null.</p>
     *
     * @param originalFileName the name of the original log file
     * @param modifiedTime the file's last modified time, used if no date is found in the name
     * @param serverName the server name to append to the renamed file
     * @return the new file name if the file is a valid log file with a date; {@code null} otherwise
     */
    public static String getRenamedFileIfTarget(String originalFileName, FileTime modifiedTime,
            String serverName) {
        if (!LogFileFilter.isTarget(originalFileName))
            return null;

        String datePart = LogFileNameHelper.extractDateFromFileName(originalFileName);

        // Skip files without a date in the name (e.g., "auth.log")
        if (datePart == null)
            return null;

        String renamedFileName =
                LogFileNameHelper.buildNewFileName(originalFileName, datePart, serverName);
        logger.info(String.format("Rename from %s to %s", originalFileName, renamedFileName));
        return renamedFileName;
    }


    
}

