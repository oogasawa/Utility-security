package com.github.oogasawa.utility.security.usn;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Checks that the live Ubuntu Security API answers this host.
 *
 * <p>
 * This program is deliberately not a JUnit test. The Ubuntu Security API is an already running
 * service that this project neither starts nor stops, so a check against it belongs to the third
 * kind of test defined by the testing standard, which is written as an ordinary Java program with a
 * {@code main} method and is kept off the Maven lifecycle. Putting such a check under
 * {@code mvn test} made every build issue requests to ubuntu.com, and the resulting load made the
 * server refuse this host.
 * </p>
 *
 * <p>
 * The check issues two requests, one to each endpoint the report depends on. Run it on demand:
 * </p>
 *
 * <pre>
 * java -cp target/Utility-security-&lt;VERSION&gt;.jar \
 *     com.github.oogasawa.utility.security.usn.UbuntuSecurityApiLiveCheck
 * </pre>
 *
 * <p>
 * The program exits with status 0 when both endpoints answered as expected, and with status 1
 * otherwise, so a shell script can branch on the result.
 * </p>
 */
public class UbuntuSecurityApiLiveCheck {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Release codename used for the check. */
    private static final String RELEASE_CODENAME = "noble";

    /** CVE used for the check. Ubuntu rates it as medium. */
    private static final String SAMPLE_CVE_ID = "CVE-2025-4207";

    /**
     * Runs the check and reports the outcome on standard output.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        boolean noticesEndpointAnswered = checkNoticesEndpoint();
        boolean cveEndpointAnswered = checkCveEndpoint();

        if (noticesEndpointAnswered && cveEndpointAnswered) {
            System.out.println("PASS: both endpoints of the Ubuntu Security API answered.");
            System.exit(0);
        }
        System.out.println("FAIL: the Ubuntu Security API did not answer as expected.");
        System.exit(1);
    }

    /**
     * Requests one notice and reports whether the response carries the fields the report reads.
     *
     * @return true when the endpoint answered with at least one notice
     */
    private static boolean checkNoticesEndpoint() {
        String url = "https://ubuntu.com/security/notices.json"
                + "?release=" + RELEASE_CODENAME + "&order=newest&limit=1";
        try {
            String body = UbuntuSecurityHttpClient.fetchJson(url);
            if (body == null) {
                System.out.println("notices endpoint: the server answered HTTP 404.");
                return false;
            }
            JsonNode notices = MAPPER.readTree(body).path("notices");
            if (!notices.isArray() || notices.isEmpty()) {
                System.out.println("notices endpoint: the response carried no notice.");
                return false;
            }
            JsonNode notice = notices.get(0);
            System.out.printf("notices endpoint: %s, published %s, type %s, %d CVEs%n",
                    notice.path("id").asText(""),
                    notice.path("published").asText(""),
                    notice.path("type").asText(""),
                    notice.path("cves_ids").size());
            return true;

        } catch (Exception e) {
            System.out.println("notices endpoint: " + e.getMessage());
            return false;
        }
    }

    /**
     * Requests one CVE and reports the priority that the report would use.
     *
     * @return true when the endpoint answered with a priority the report ranks
     */
    private static boolean checkCveEndpoint() {
        try {
            String priority = UbuntuPriorityFetcher.fetchUbuntuPriority(SAMPLE_CVE_ID);
            System.out.printf("cve endpoint: %s has priority %s%n", SAMPLE_CVE_ID, priority);
            return !UbuntuPriorityFetcher.UNKNOWN_PRIORITY.equals(priority);

        } catch (Exception e) {
            System.out.println("cve endpoint: " + e.getMessage());
            return false;
        }
    }
}
