package com.github.oogasawa.utility.security.log;

import java.util.List;
import java.util.regex.Pattern;

/**
 * A utility class that determines whether a given file name matches
 * any of the known patterns for system log files.
 *
 * <p>This class delegates pattern definition to {@link LogFileFilterBuilder},
 * and uses precompiled {@link Pattern} objects for efficient matching.</p>
 */
class LogFileFilter {

    /** A list of regular expression patterns representing known log file formats. */
    private static final List<Pattern> targetPatterns = LogFileFilterBuilder.buildDefaultPatterns();

    /**
     * Checks if the given file name matches any of the known log file patterns.
     *
     * @param fileName the name of the file to test
     * @return {@code true} if the file name matches a known log pattern; {@code false} otherwise
     */
    public static boolean isTarget(String fileName) {
        // Check against all target patterns
        for (Pattern pattern : targetPatterns) {
            if (pattern.matcher(fileName).matches()) {
                return true;
            }
        }
        return false;
    }

}
