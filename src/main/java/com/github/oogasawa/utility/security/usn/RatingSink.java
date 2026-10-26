package com.github.oogasawa.utility.security.usn;

import java.io.IOException;
import java.util.List;

/**
 * Receives the rating of one notice as soon as it is known.
 *
 * <p>
 * Looking up the CVEs of a notice can take hours when ubuntu.com is slow, so a rating that has
 * been obtained is handed over at once rather than kept until every notice has been rated.
 * </p>
 */
@FunctionalInterface
public interface RatingSink {

    /**
     * Accepts the rating of one notice.
     *
     * @param noticeId the identifier of the notice, for example {@code USN-8933-1}
     * @param severity the severity of the notice
     * @param severeCves the CVEs of the notice whose priority is High or Critical
     * @throws IOException if the rating cannot be kept
     */
    void accept(String noticeId, String severity, List<String> severeCves) throws IOException;
}
