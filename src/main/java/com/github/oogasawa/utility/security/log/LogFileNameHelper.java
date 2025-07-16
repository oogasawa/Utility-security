package com.github.oogasawa.utility.security.log;

import java.nio.file.attribute.FileTime;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * A utility class for handling log file name transformations, such as
 * extracting rotation dates and generating new file names that include
 * the server name and date.
 */
class LogFileNameHelper {

    /**
     * Extracts an 8-digit date (yyyyMMdd format) from a log file name if present.
     *
     * <p>This method uses a regular expression to search for a sequence of 8 digits
     * anywhere in the file name, which is assumed to represent a date.</p>
     *
     * @param fileName the original file name
     * @return the extracted date string (yyyyMMdd), or {@code null} if no date is found
     */
    public static String extractDateFromFileName(String fileName) {
        String datePattern = ".*?(\\d{8}).*";
        if (fileName.matches(datePattern)) {
            return fileName.replaceAll(datePattern, "$1");
        }
        return null;
    }

    /**
     * Converts the file's last modified time to a date string in yyyyMMdd format.
     *
     * @param time the file's last modified time
     * @return a string representation of the date (yyyyMMdd)
     */
    public static String getDateFromTimestamp(FileTime time) {
        return new SimpleDateFormat("yyyyMMdd").format(new Date(time.toMillis()));
    }

    /**
     * Constructs a new log file name by appending the given date and server name.
     *
     * <p>The format of the resulting file name is: {@code originalName_yyyyMMdd_serverName}.</p>
     *
     * @param baseName the original file name
     * @param date     the date to append (format: yyyyMMdd)
     * @param server   the server name to append
     * @return the newly constructed file name
     */
    public static String buildNewFileName(String baseName, String date, String server) {
        // Avoid adding duplicate date if already present in the name
        if (baseName.contains(date)) {
            return baseName + "_" + server;
        } else {
            return baseName + "_" + date + "_" + server;
        }
    }

}

