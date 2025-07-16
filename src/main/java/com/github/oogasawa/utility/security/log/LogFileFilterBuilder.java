package com.github.oogasawa.utility.security.log;

import java.util.*;
import java.util.regex.Pattern;

/**
 * A utility class for building regular expression patterns used to identify
 * relevant system log files based on their filenames.
 *
 * <p>This class provides a centralized way to manage log filename patterns,
 * making it easy to extend or modify the list of supported log types.</p>
 */
class LogFileFilterBuilder {

    /**
     * Builds and returns a list of compiled regular expression patterns
     * that match typical Linux system log file names.
     *
     * <p>The patterns cover common log files including:
     * <ul>
     *   <li>Apache logs (e.g. {@code access.log}, {@code error.log})</li>
     *   <li>System logs (e.g. {@code auth.log}, {@code syslog}, {@code kern.log})</li>
     *   <li>journal-export logs (e.g. {@code journal-YYYYMMDD.log})</li>
     *   <li>Package and upgrade logs (e.g. {@code dpkg.log}, {@code apport.log})</li>
     *   <li>System statistics logs (e.g. {@code saNN}, {@code sarNN})</li>
     *   <li>APT history and unattended upgrade logs</li>
     * </ul>
     * </p>
     *
     * @return a list of {@link Pattern} objects representing the known log filename formats
     */
    public static List<Pattern> buildDefaultPatterns() {
        List<String> patterns = new ArrayList<>();

        // Apache logs
        patterns.add("access\\.log(\\..*|-[0-9]{8}\\.gz)?$");
        patterns.add("error\\.log(\\..*|-[0-9]{8}\\.gz)?$");

        // Generic system logs
        patterns.add("(auth|kern|syslog|ufw|dmesg)(\\..*|-\\d{8})?$");

        // journal-export logs
        patterns.add("journal-\\d{8}\\.log(\\.\\d+\\.gz)?$");

        // Package manager logs
        patterns.add("dpkg\\.log$");
        patterns.add("alternatives\\.log$");
        patterns.add("apport\\.log$");
        patterns.add("ubuntu-advantage\\.log$");

        // sysstat logs
        patterns.add("sa\\d+$");
        patterns.add("sar\\d+$");

        // APT and unattended upgrade logs
        patterns.add("history\\.log$");
        patterns.add("term\\.log$");
        patterns.add("unattended-upgrades.*\\.log$");

        // Compile regex strings to Pattern objects
        List<Pattern> compiled = new ArrayList<>();
        for (String regex : patterns) {
            compiled.add(Pattern.compile(regex));
        }

        return compiled;
    }
}
