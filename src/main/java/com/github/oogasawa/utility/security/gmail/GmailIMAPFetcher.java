package com.github.oogasawa.utility.security.gmail;

import jakarta.mail.BodyPart;
import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.Session;
import jakarta.mail.Store;
import jakarta.mail.search.AndTerm;
import jakarta.mail.search.ComparisonTerm;
import jakarta.mail.search.FromTerm;
import jakarta.mail.search.ReceivedDateTerm;
import jakarta.mail.search.SearchTerm;
import jakarta.mail.search.SubjectTerm;
import jakarta.mail.internet.InternetAddress;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.Objects;
import java.util.Properties;
import org.jsoup.Jsoup;

/**
 * Fetches Ubuntu security announce digests from Gmail and concatenates them into a text file.
 */
public final class GmailIMAPFetcher {

    private static final String HOST = "imap.gmail.com";
    private static final String DIGEST_SUBJECT_TOKEN = "ubuntu-security-announce Digest, Vol";
    private static final String DEFAULT_FOLDER = "INBOX";
    private static final ZoneId ZONE = ZoneId.systemDefault();
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ISO_LOCAL_DATE;

    private GmailIMAPFetcher() {
        // Utility class
    }

    /**
     * CLI entry point for ad-hoc execution without the surrounding application.
     *
     * @param args {@code <start-date> <end-date> <output-file>} parameters using ISO date format
     * @throws Exception if validation fails or the fetcher cannot connect to Gmail
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: GmailIMAPFetcher <start-date> <end-date> <output-file>");
            System.err.println("Dates must use YYYY-MM-DD. Output file is overwritten if present.");
            System.exit(1);
        }

        LocalDate start = LocalDate.parse(args[0], DATE_FORMAT);
        LocalDate end = LocalDate.parse(args[1], DATE_FORMAT);
        if (end.isBefore(start)) {
            throw new IllegalArgumentException("End date must be the same as or after start date.");
        }

        Path output = Path.of(args[2]);
        String user = requireEnv("GMAIL_USERNAME");
        String password = requireEnv("GMAIL_APP_PASSWORD");

        fetchAndSave(start, end, output, user, password);
    }

    /**
     * Downloads digest emails in the provided date range, concatenates their text bodies, and writes
     * the result to the requested output file.
     *
     * @param start inclusive start date in the system default zone
     * @param end inclusive end date in the system default zone
     * @param output target path where the concatenated text will be written
     * @param user Gmail username (usually the full email address)
     * @param password Gmail app password to authenticate against IMAPS
     * @throws MessagingException if IMAP operations fail
     * @throws IOException if reading or writing message content fails
     */
    public static void fetchAndSave(LocalDate start, LocalDate end, Path output, String user, String password)
            throws MessagingException, IOException {
        Objects.requireNonNull(output, "output");
        Properties props = new Properties();
        props.put("mail.store.protocol", "imaps");
        props.put("mail.imaps.host", HOST);
        props.put("mail.imaps.port", "993");
        props.put("mail.imaps.ssl.enable", "true");

        Session session = Session.getDefaultInstance(props);
        Store store = null;
        Folder inbox = null;
        try {
            store = session.getStore("imaps");
            store.connect(HOST, user, password);

            inbox = store.getFolder(DEFAULT_FOLDER);
            inbox.open(Folder.READ_ONLY);

            Message[] messages = inbox.search(buildSearchTerm(start, end));
            Arrays.sort(messages, Comparator.comparing(GmailIMAPFetcher::safeReceivedDate));

            StringBuilder builder = new StringBuilder();
            for (Message message : messages) {
                String body = extractText(message).trim();
                if (body.isEmpty()) {
                    continue;
                }

                if (builder.length() > 0) {
                    builder.append(System.lineSeparator()).append(System.lineSeparator());
                    builder.append("-----").append(System.lineSeparator()).append(System.lineSeparator());
                }

                Date receivedDate = safeReceivedDate(message);
                builder.append("Subject: ")
                        .append(message.getSubject() == null ? "(no subject)" : message.getSubject())
                        .append(System.lineSeparator());
                builder.append("Date: ")
                        .append(DATE_FORMAT.format(receivedDate.toInstant().atZone(ZONE).toLocalDate()))
                        .append(System.lineSeparator());
                builder.append(System.lineSeparator());
                builder.append(body);
            }

            if (builder.length() == 0) {
                builder.append("No messages matched criteria between ")
                        .append(start.format(DATE_FORMAT)).append(" and ")
                        .append(end.format(DATE_FORMAT)).append('.')
                        .append(System.lineSeparator());
            }

            if (output.getParent() != null) {
                Files.createDirectories(output.getParent());
            }

            Files.writeString(output, builder.toString(), StandardCharsets.UTF_8);
        } finally {
            if (inbox != null && inbox.isOpen()) {
                inbox.close(false);
            }
            if (store != null && store.isConnected()) {
                store.close();
            }
        }
    }

    /**
     * Builds an IMAP {@link SearchTerm} that narrows results to Ubuntu digest mails in the desired
     * date range.
     *
     * @param start inclusive start date for the IMAP search
     * @param end inclusive end date for the IMAP search
     * @return combined search criteria covering sender, subject token, and received date window
     * @throws MessagingException if address validation fails while creating the {@link FromTerm}
     */
    private static SearchTerm buildSearchTerm(LocalDate start, LocalDate end) throws MessagingException {
        Date startDate = Date.from(start.atStartOfDay(ZONE).toInstant());
        Date endExclusive = Date.from(end.plusDays(1).atStartOfDay(ZONE).toInstant());

        SearchTerm fromUbuntu = new FromTerm(new InternetAddress("security-announce@lists.ubuntu.com"));
        SearchTerm subjectDigest = new SubjectTerm(DIGEST_SUBJECT_TOKEN);
        SearchTerm notBefore = new ReceivedDateTerm(ComparisonTerm.GE, startDate);
        SearchTerm before = new ReceivedDateTerm(ComparisonTerm.LT, endExclusive);

        return new AndTerm(new SearchTerm[]{fromUbuntu, subjectDigest, notBefore, before});
    }

    /**
     * Returns a resilient received timestamp, falling back to the sent date or epoch if necessary.
     *
     * @param message mail message whose timestamp is required
     * @return received date, sent date, or the epoch if neither is available
     */
    private static Date safeReceivedDate(Message message) {
        try {
            Date received = message.getReceivedDate();
            if (received != null) {
                return received;
            }
            Date sent = message.getSentDate();
            if (sent != null) {
                return sent;
            }
            return new Date(0L);
        } catch (MessagingException e) {
            return new Date(0L);
        }
    }

    /**
     * Recursively extracts human-readable text from plain, HTML, or multipart messages.
     *
     * @param part the message part to inspect
     * @return textual representation of the part, or an empty string when none is available
     * @throws MessagingException if the mail API encounters errors while parsing
     * @throws IOException if stream access fails while reading part content
     */
    private static String extractText(Part part) throws MessagingException, IOException {
        if (part.isMimeType("text/plain")) {
            Object content = part.getContent();
            return content == null ? "" : content.toString();
        }

        if (part.isMimeType("text/html")) {
            Object content = part.getContent();
            return content == null ? "" : Jsoup.parse(content.toString()).text();
        }

        if (part.isMimeType("multipart/*")) {
            Multipart multipart = (Multipart) part.getContent();
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < multipart.getCount(); i++) {
                BodyPart bodyPart = multipart.getBodyPart(i);
                String text = extractText(bodyPart);
                if (!text.isBlank()) {
                    if (builder.length() > 0) {
                        builder.append(System.lineSeparator());
                    }
                    builder.append(text.trim());
                }
            }
            return builder.toString();
        }

        return "";
    }

    /**
     * Retrieves an environment variable, failing fast when the variable is undefined.
     *
     * @param name environment variable to look up
     * @return non-blank value associated with {@code name}
     * @throws IllegalStateException if the variable is absent or blank
     */
    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Environment variable " + name + " must be set.");
        }
        return value;
    }
}
