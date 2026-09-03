package com.github.oogasawa.utility.security.usn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link UbuntuPriorityFetcher}.
 *
 * <p>
 * These tests touch no external service. They feed the parsing methods with pages of the shape that
 * {@code https://ubuntu.com/security/<CVE id>} returns, so the mapping from what the page shows to
 * the value used by the report is verified without issuing a request. Whether the live pages answer
 * is checked by {@code UbuntuSecurityApiLiveCheck}, which is run on demand.
 * </p>
 */
@DisplayName("UbuntuPriorityFetcher — the Ubuntu CVE priority read from the page of a CVE")
public class UbuntuPriorityFetcherTest {

    /** The part of a CVE page that shows the priority Ubuntu assigned, as the site writes it. */
    private static final String PAGE_WITH_MEDIUM = """
            <div>
              <p class="p-text--small-caps">Ubuntu priority</p>
              <div class="p-heading-icon--small">
                <img src="https://res.cloudinary.com/image/fetch/f_svg/https%3A%2F%2Fassets.ubuntu.com%2Fv1%2F8010f9e0-CVE-Priority-icon-Medium.svg" alt="" width="16" height="16" />
                <p>Medium</p>
              </div>
              <p><a href="/security/cves/about#priority">Why this priority?</a></p>
            </div>
            """;

    /** A page that shows more than one priority icon. */
    private static final String PAGE_WITH_AN_EARLIER_ICON = """
            <div class="related">
              <img src="https://assets.ubuntu.com/v1/CVE-Priority-icon-Low.svg" alt="" />
            </div>
            <div>
              <p class="p-text--small-caps">Ubuntu priority</p>
              <img src="https://assets.ubuntu.com/v1/CVE-Priority-icon-Critical.svg" alt="" />
            </div>
            """;

    /** A page of a CVE that Ubuntu rates as negligible. */
    private static final String PAGE_WITH_NEGLIGIBLE = """
            <p class="p-text--small-caps">Ubuntu priority</p>
            <img src="https://assets.ubuntu.com/v1/CVE-Priority-icon-Negligible.svg" alt="" />
            """;

    /** A page that shows no priority icon at all. */
    private static final String PAGE_WITHOUT_AN_ICON = """
            <div>
              <p class="p-text--small-caps">Ubuntu priority</p>
              <p>This CVE is not known to affect any Ubuntu release.</p>
            </div>
            """;

    @Test
    @DisplayName("The priority is read from the name of the icon file")
    void extractPriority_pageShowingMedium_returnsMedium() {
        assertEquals("Medium", UbuntuPriorityFetcher.extractPriority(PAGE_WITH_MEDIUM));
    }

    @Test
    @DisplayName("The first icon of the page is the one taken")
    void extractPriority_pageWithSeveralIcons_takesTheFirst() {
        assertEquals("Low", UbuntuPriorityFetcher.extractPriority(PAGE_WITH_AN_EARLIER_ICON));
    }

    @Test
    @DisplayName("A negligible priority is reported as Unknown, as this class has always done")
    void extractPriority_pageShowingNegligible_returnsUnknown() {
        assertEquals(UbuntuPriorityFetcher.UNKNOWN_PRIORITY,
                UbuntuPriorityFetcher.extractPriority(PAGE_WITH_NEGLIGIBLE));
    }

    @Test
    @DisplayName("A page without a priority icon is reported as Unknown")
    void extractPriority_pageWithoutAnIcon_returnsUnknown() {
        assertEquals(UbuntuPriorityFetcher.UNKNOWN_PRIORITY,
                UbuntuPriorityFetcher.extractPriority(PAGE_WITHOUT_AN_ICON));
    }

    @Test
    @DisplayName("A page that could not be read at all is reported as Unknown")
    void extractPriority_null_returnsUnknown() {
        assertEquals(UbuntuPriorityFetcher.UNKNOWN_PRIORITY,
                UbuntuPriorityFetcher.extractPriority(null));
    }

    @Test
    @DisplayName("Every priority that the report ranks is mapped to its capitalized form")
    void normalizePriority_rankedValues_returnsCapitalizedForm() {
        assertEquals("Low", UbuntuPriorityFetcher.normalizePriority("low"));
        assertEquals("Medium", UbuntuPriorityFetcher.normalizePriority("medium"));
        assertEquals("High", UbuntuPriorityFetcher.normalizePriority("high"));
        assertEquals("Critical", UbuntuPriorityFetcher.normalizePriority("critical"));
    }

    @Test
    @DisplayName("Surrounding whitespace and letter case do not change the result")
    void normalizePriority_mixedCaseWithWhitespace_returnsCapitalizedForm() {
        assertEquals("High", UbuntuPriorityFetcher.normalizePriority("  HIGH  "));
    }

    @Test
    @DisplayName("A value the report does not rank is reported as Unknown")
    void normalizePriority_unrankedValue_returnsUnknown() {
        assertEquals(UbuntuPriorityFetcher.UNKNOWN_PRIORITY,
                UbuntuPriorityFetcher.normalizePriority("untriaged"));
    }

    @Test
    @DisplayName("A null value is reported as Unknown")
    void normalizePriority_null_returnsUnknown() {
        assertEquals(UbuntuPriorityFetcher.UNKNOWN_PRIORITY,
                UbuntuPriorityFetcher.normalizePriority(null));
    }

    @Test
    @DisplayName("A blank CVE identifier is rejected before any request is issued")
    void fetchUbuntuPriority_blankCveId_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> UbuntuPriorityFetcher.fetchUbuntuPriority("   "));
    }
}
