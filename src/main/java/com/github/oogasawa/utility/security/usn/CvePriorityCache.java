package com.github.oogasawa.utility.security.usn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Stores the priority that Ubuntu assigns to a CVE, so that the same CVE is requested once rather
 * than once per run.
 *
 * <p>
 * A report for one week refers to roughly one hundred CVEs, and the endpoint that returns one CVE
 * answers slowly and sometimes fails. The same CVE also appears in several notices and in the
 * reports of following weeks, because a kernel notice is reissued for each kernel flavour. Reading
 * a stored value instead of repeating the request removes both the waiting and the risk that a
 * temporary server fault turns into a wrong severity.
 * </p>
 *
 * <h2>What is stored and what is not</h2>
 *
 * <p>
 * Only the four priorities that the report ranks are stored: {@code Low}, {@code Medium},
 * {@code High} and {@code Critical}. These are the outcome of a completed triage by Ubuntu and do
 * not normally change afterwards.
 * </p>
 *
 * <p>
 * A CVE that Ubuntu has not ranked, or that the tracker does not hold, is deliberately not stored.
 * Such a CVE can be ranked later, and storing the earlier answer would keep the report from ever
 * seeing the new one. A failed request is not stored either, because it says nothing about the CVE.
 * </p>
 *
 * <h2>When the file is written</h2>
 *
 * <p>
 * A line is appended as soon as a priority is known, not at the end of the run. A report for one
 * week takes fifteen to twenty minutes, and a run that is interrupted part way would otherwise lose
 * every priority obtained until then. At the end of a run the file is rewritten sorted by CVE
 * identifier and without repeated identifiers, which tidies what an interrupted run left behind.
 * </p>
 *
 * <p>
 * The file is a table of two tab separated columns, the CVE identifier and its priority. Deleting
 * the file makes the next run request every CVE again.
 * </p>
 */
public class CvePriorityCache {

    private static final Logger logger = LoggerFactory.getLogger(CvePriorityCache.class);

    /** Priorities that are stored. Any other answer is requested again on the next run. */
    private static final List<String> STORABLE_PRIORITIES =
            List.of("Low", "Medium", "High", "Critical");

    private final Path cacheFile;
    private final Map<String, String> priorityByCveId = new TreeMap<String, String>();

    /**
     * Creates a cache backed by the given file. The file is not read until {@link #load()} is
     * called.
     *
     * @param cacheFile the file that holds the stored priorities
     */
    public CvePriorityCache(Path cacheFile) {
        if (cacheFile == null) {
            throw new IllegalArgumentException("Cache file must not be null");
        }
        this.cacheFile = cacheFile;
    }

    /**
     * Returns the file used when the caller does not name one.
     *
     * @return {@code $HOME/.cache/Utility-security/cve-priority.tsv}
     */
    public static Path defaultCacheFile() {
        return Path.of(System.getProperty("user.home"), ".cache", "Utility-security",
                "cve-priority.tsv");
    }

    /**
     * Reads the stored priorities.
     *
     * <p>
     * A missing file is not an error; it means nothing has been stored yet. A malformed line is
     * skipped with a warning, so a damaged file costs requests rather than the whole run.
     * </p>
     */
    public void load() {
        if (!Files.isRegularFile(this.cacheFile)) {
            logger.info("No stored CVE priorities at {}", this.cacheFile);
            return;
        }
        try {
            List<String> lines = Files.readAllLines(this.cacheFile, StandardCharsets.UTF_8);
            int malformed = 0;
            for (String line : lines) {
                if (line.isBlank()) {
                    continue;
                }
                String[] columns = line.split("\t", -1);
                if (columns.length != 2 || columns[0].isBlank()
                        || !STORABLE_PRIORITIES.contains(columns[1])) {
                    malformed++;
                    continue;
                }
                this.priorityByCveId.put(columns[0].trim(), columns[1]);
            }
            logger.info("Loaded {} stored CVE priorities from {} ({} malformed lines skipped)",
                    this.priorityByCveId.size(), this.cacheFile, malformed);

        } catch (IOException e) {
            logger.warn("Could not read {}: {}. Every CVE will be requested.",
                    this.cacheFile, e.getMessage());
        }
    }

    /**
     * Returns the stored priority of the given CVE.
     *
     * @param cveId the CVE identifier
     * @return the stored priority, or {@code null} when nothing is stored for it
     */
    public String get(String cveId) {
        return this.priorityByCveId.get(cveId);
    }

    /**
     * Stores the priority of the given CVE when it is one of the ranked priorities, and writes it
     * to the file at once.
     *
     * <p>
     * The line is appended as soon as the priority is known rather than at the end of the run. A
     * report for one week takes fifteen to twenty minutes, and the endpoint that answers with a CVE
     * fails often enough that a run can be interrupted part way. Writing only at the end would
     * throw away every priority obtained until then, which is exactly what the file exists to
     * prevent.
     * </p>
     *
     * @param cveId the CVE identifier
     * @param priority the priority answered by the Ubuntu Security API
     */
    public void put(String cveId, String priority) {
        if (cveId == null || cveId.isBlank() || !STORABLE_PRIORITIES.contains(priority)) {
            return;
        }
        String previous = this.priorityByCveId.put(cveId, priority);
        if (priority.equals(previous)) {
            return;
        }
        append(cveId, priority);
    }

    /**
     * Appends one line to the file.
     *
     * <p>
     * A failure to write is reported and does not end the run. The report being produced is worth
     * more than the stored priorities, which only save time on the next run.
     * </p>
     *
     * @param cveId the CVE identifier
     * @param priority the priority to record
     */
    private void append(String cveId, String priority) {
        try {
            Path parent = this.cacheFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(this.cacheFile,
                    cveId + "\t" + priority + System.lineSeparator(),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        } catch (IOException e) {
            logger.warn("Could not append the priority of {} to {}: {}",
                    cveId, this.cacheFile, e.getMessage());
        }
    }

    /**
     * Rewrites the file sorted by CVE identifier and without repeated identifiers.
     *
     * <p>
     * Every priority is already in the file, because {@link #put(String, String)} appends it as
     * soon as it is known. This method only tidies what an interrupted run left behind: lines in
     * the order they were obtained, and possibly the same identifier more than once.
     * </p>
     */
    public void save() {
        if (this.priorityByCveId.isEmpty()) {
            logger.info("No CVE priority to store in {}", this.cacheFile);
            return;
        }
        try {
            Path parent = this.cacheFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            try (BufferedWriter writer =
                    Files.newBufferedWriter(this.cacheFile, StandardCharsets.UTF_8)) {
                for (Map.Entry<String, String> entry : this.priorityByCveId.entrySet()) {
                    writer.write(entry.getKey());
                    writer.write('\t');
                    writer.write(entry.getValue());
                    writer.newLine();
                }
            }
            logger.info("Rewrote {} with {} CVE priorities, sorted and without repetition",
                    this.cacheFile, this.priorityByCveId.size());

        } catch (IOException e) {
            logger.warn("Could not write {}: {}", this.cacheFile, e.getMessage());
        }
    }

    /**
     * Returns how many priorities are held.
     *
     * @return the number of stored CVE identifiers
     */
    public int size() {
        return this.priorityByCveId.size();
    }

    /**
     * Returns the identifiers held, in order.
     *
     * @return an unmodifiable list of the stored CVE identifiers
     */
    public List<String> storedCveIds() {
        return Collections.unmodifiableList(new ArrayList<String>(this.priorityByCveId.keySet()));
    }
}
