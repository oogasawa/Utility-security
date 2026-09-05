package com.github.oogasawa.utility.security.usn;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Stores the notices already obtained from the Ubuntu Security API, so that a report covering an
 * earlier period does not page through every notice published since.
 *
 * <h2>Why the notices are stored</h2>
 *
 * <p>
 * The endpoint that lists notices returns twenty at a time and takes no date, so reaching a notice
 * published a year ago means asking for every page in between. Filling the period from August 2025
 * onwards issued 146 requests for the lists alone, spread over twenty four minutes, and every one
 * of those pages had been read on an earlier run. What a notice says does not change after it is
 * published: a correction is published as a new notice with its own identifier.
 * </p>
 *
 * <h2>How much is read from the server anyway</h2>
 *
 * <p>
 * A run always asks for the newest page and keeps asking until it reaches a page whose notices are
 * all stored. Notices published since the last run are picked up that way, and the newest pages are
 * read afresh each time, so an edit Canonical makes to a recent notice is not missed. Paging stops
 * there only when the stored notices reach back past the start of the period; otherwise the run
 * continues to the start as before.
 * </p>
 *
 * <h2>The shape of the file</h2>
 *
 * <p>
 * One notice per line, as the JSON object the API returned, in
 * {@code $HOME/.cache/Utility-security/notices-<release>.jsonl}. A line is written as soon as its
 * page arrives, so a run that is interrupted keeps what it had read. Deleting the file makes the
 * next run read every page again.
 * </p>
 */
public class NoticeCache {

    private static final Logger logger = LoggerFactory.getLogger(NoticeCache.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path file;

    /** The notices, by identifier, in the order they were read. */
    private final Map<String, JsonNode> notices = new LinkedHashMap<String, JsonNode>();

    /**
     * Opens the cache of one Ubuntu release, reading whatever earlier runs left in it.
     *
     * @param releaseCodename the Ubuntu release codename, for example {@code noble}
     */
    public NoticeCache(String releaseCodename) {
        this(defaultFile(releaseCodename));
    }

    /**
     * Opens a cache held in a named file. Tests use this to work in a directory of their own.
     *
     * @param file the file to read and append to
     */
    public NoticeCache(Path file) {
        this.file = file;
        load();
    }

    /**
     * The file a release uses when none is named.
     *
     * @param releaseCodename the Ubuntu release codename
     * @return the path of the file
     */
    static Path defaultFile(String releaseCodename) {
        return Path.of(System.getProperty("user.home"), ".cache", "Utility-security",
                "notices-" + releaseCodename + ".jsonl");
    }

    private void load() {
        if (!Files.isReadable(this.file)) {
            logger.info("No stored notices at {}", this.file);
            return;
        }
        int malformed = 0;
        try {
            for (String line : Files.readAllLines(this.file, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    JsonNode notice = MAPPER.readTree(line);
                    String id = notice.path("id").asText("");
                    if (id.isEmpty()) {
                        malformed++;
                        continue;
                    }
                    this.notices.put(id, notice);
                } catch (IOException e) {
                    malformed++;
                }
            }
        } catch (IOException e) {
            logger.warn("Could not read the stored notices at {}: {}", this.file, e.getMessage());
            return;
        }
        logger.info("Loaded {} stored notices from {} ({} malformed lines skipped)",
                this.notices.size(), this.file, malformed);
    }

    /**
     * Whether a notice is already stored.
     *
     * @param id the notice identifier, for example {@code USN-8666-1}
     * @return true when it is
     */
    public boolean holds(String id) {
        return this.notices.containsKey(id);
    }

    /**
     * How many notices are stored.
     *
     * @return the count
     */
    public int size() {
        return this.notices.size();
    }

    /**
     * Adds a notice, writing it to the file at once, and replaces a notice of the same identifier
     * that was already there.
     *
     * @param notice the notice as the API returned it
     */
    public void put(JsonNode notice) {
        String id = notice.path("id").asText("");
        if (id.isEmpty()) {
            return;
        }
        JsonNode previous = this.notices.put(id, notice);
        if (previous != null && previous.equals(notice)) {
            return;
        }
        append(notice);
    }

    private void append(JsonNode notice) {
        try {
            Files.createDirectories(this.file.getParent());
            try (BufferedWriter out = Files.newBufferedWriter(this.file, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                out.write(MAPPER.writeValueAsString(notice));
                out.newLine();
            }
        } catch (IOException e) {
            logger.warn("Could not store the notice {}: {}", notice.path("id").asText(""),
                    e.getMessage());
        }
    }

    /**
     * The earliest publication date among the stored notices.
     *
     * <p>
     * Because the store is only ever extended by reading pages from the newest backwards, every
     * notice published after this date is stored. That is what lets a run stop paging.
     * </p>
     *
     * @return the date, or null when nothing is stored
     */
    public LocalDate earliestPublished() {
        LocalDate earliest = null;
        for (JsonNode notice : this.notices.values()) {
            LocalDate published = UsnApiFetcher.publishedDateOf(notice);
            if (published != null && (earliest == null || published.isBefore(earliest))) {
                earliest = published;
            }
        }
        return earliest;
    }

    /**
     * The stored notices published within a period, newest first.
     *
     * @param start the first publication date to include, inclusive
     * @param end the last publication date to include, inclusive
     * @return the notices
     */
    public List<JsonNode> between(LocalDate start, LocalDate end) {
        List<JsonNode> found = new ArrayList<JsonNode>();
        for (JsonNode notice : this.notices.values()) {
            LocalDate published = UsnApiFetcher.publishedDateOf(notice);
            if (published == null || published.isBefore(start) || published.isAfter(end)) {
                continue;
            }
            found.add(notice);
        }
        found.sort(Comparator.comparing(
                (JsonNode n) -> UsnApiFetcher.publishedDateOf(n)).reversed()
                .thenComparing(n -> n.path("id").asText("")));
        return found;
    }

    /**
     * Rewrites the file with one line per notice and no repeated identifier, which tidies what an
     * interrupted run left behind.
     */
    public void save() {
        try {
            Files.createDirectories(this.file.getParent());
            List<String> lines = new ArrayList<String>();
            for (JsonNode notice : this.notices.values()) {
                lines.add(MAPPER.writeValueAsString(notice));
            }
            Files.write(this.file, lines, StandardCharsets.UTF_8);
            logger.info("Rewrote {} with {} notices and without repetition", this.file,
                    this.notices.size());
        } catch (IOException e) {
            logger.warn("Could not rewrite {}: {}", this.file, e.getMessage());
        }
    }
}
