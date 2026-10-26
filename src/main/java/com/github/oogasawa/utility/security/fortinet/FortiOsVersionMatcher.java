package com.github.oogasawa.utility.security.fortinet;

import java.util.List;

/**
 * Tells whether a FortiOS version falls in the affected ranges that a FortiGuard advisory lists.
 *
 * <p>
 * An advisory writes an affected range in one of three forms, as the product id of its CSAF file:
 * {@code FortiOS 7.4 all versions}, {@code FortiOS >=7.4.0|<=7.4.8}, or a single version such as
 * {@code FortiOS 7.6.0}.
 * </p>
 */
public final class FortiOsVersionMatcher {

    /** The answer for one version. */
    public enum Answer {
        /** The version is in an affected range. */
        AFFECTED,
        /** No affected range holds the version. */
        NOT_AFFECTED,
        /** A range was written in a form this class does not know, so a person has to look. */
        CHECK
    }

    private FortiOsVersionMatcher() {
    }

    /**
     * Checks a version against the affected product ids of one advisory.
     *
     * @param version a FortiOS version such as {@code 7.4.6}
     * @param affectedProductIds the {@code known_affected} product ids of the advisory
     * @return the answer
     */
    public static Answer check(String version, List<String> affectedProductIds) {
        boolean unknownForm = false;
        for (String id : affectedProductIds) {
            if (!id.startsWith("FortiOS ")) {
                continue;
            }
            String range = id.substring("FortiOS ".length()).trim();
            if (range.startsWith("upcoming")) {
                continue;
            }
            Boolean hit = matches(version, range);
            if (hit == null) {
                unknownForm = true;
            } else if (hit) {
                return Answer.AFFECTED;
            }
        }
        return unknownForm ? Answer.CHECK : Answer.NOT_AFFECTED;
    }

    /** Returns null when the range is written in a form not known. */
    private static Boolean matches(String version, String range) {
        try {
            if (range.endsWith(" all versions")) {
                String branch = range.substring(0, range.length() - " all versions".length()).trim();
                return version.equals(branch) || version.startsWith(branch + ".");
            }
            if (range.startsWith(">=") && range.contains("|<")) {
                String[] parts = range.split("\\|");
                String lower = parts[0].substring(2);
                boolean inclusive = parts[1].startsWith("<=");
                String upper = parts[1].substring(inclusive ? 2 : 1);
                int low = compare(version, lower);
                int high = compare(version, upper);
                return low >= 0 && (inclusive ? high <= 0 : high < 0);
            }
            if (range.matches("\\d+(\\.\\d+)*")) {
                return compare(version, range) == 0;
            }
        } catch (NumberFormatException e) {
            return null;
        }
        return null;
    }

    /** Compares dotted numbers, treating a missing part as zero. */
    static int compare(String a, String b) {
        String[] x = a.split("\\.");
        String[] y = b.split("\\.");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            int p = i < x.length ? Integer.parseInt(x[i]) : 0;
            int q = i < y.length ? Integer.parseInt(y[i]) : 0;
            if (p != q) {
                return Integer.compare(p, q);
            }
        }
        return 0;
    }
}
