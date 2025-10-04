package com.github.oogasawa.utility.security;


import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import com.github.oogasawa.utility.cli.CommandRepository;
import com.github.oogasawa.utility.security.gmail.GmailIMAPFetcher;
import com.github.oogasawa.utility.security.log.LogRenamer;
import com.github.oogasawa.utility.security.usn.USNJsonExporter;
import jakarta.mail.MessagingException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;


/**
 * Entry point and command registry for the Utility-security CLI application.
 *
 * <p>This class wires log maintenance, Ubuntu Security Notice reporting, and Gmail digest
 * retrieval commands into a shared {@link CommandRepository}. It is the central hub invoked when
 * running the shaded jar.</p>
 */
public class App {

    /**
     * The command-line usage synopsis displayed when no command is provided.
     */
    String synopsis = "java -jar your_program-<VERSION>-fat.jar <command> <options>";
    
    /**
     * The repository that holds command definitions and executes them.
     */
    CommandRepository cmds = new CommandRepository();

    /**
     * Initializes the command repository and dispatches the parsed command to its handler.
     *
     * @param args arguments supplied via the command line
     */
    public static void main(String[] args) {
        App app = new App();

        // Load the command definitions.
        app.setupCommands();

        try {
            CommandLine cl = app.cmds.parse(args);
            String command = app.cmds.getGivenCommand();

            if (command == null) {
                app.cmds.printCommandList(app.synopsis);
            } else if (app.cmds.hasCommand(command)) {
                app.cmds.execute(command, cl);
            } else {
                System.err.println("Error: Unknown command: " + app.cmds.getGivenCommand());
                System.err.println("Use one of the available commands listed below:");
                app.cmds.printCommandList(app.synopsis);
            }
        } catch (ParseException e) {
            System.err.println("Error: Failed to parse the command. Reason: " + e.getMessage());
            System.err.println("See the help below for correct usage:");
            app.cmds.printCommandHelp(app.cmds.getGivenCommand());
        }
    }



    /**
     * Registers all available commands by invoking their respective setup methods.
     */
    public void setupCommands() {

        logRenameCommand();
        ubuntuSecurityReportCommand();
        gmailDigestFetchCommand();
        
    }
    
    /**
     * Registers the {@code log:rename} command that normalizes log file names.
     */
    public void logRenameCommand() {
        Options opts = new Options();

        opts.addOption(Option.builder("s")
                .longOpt("srcDir")
                .hasArg(true)
                .argName("srcDir")
                .desc("The source directory of the log files.")
                .required(true)
                .build());

        opts.addOption(Option.builder("d")
                .longOpt("destDir")
                .hasArg(true)
                .argName("destDir")
                .desc("The destination directory of the log files.")
                .required(true)
                .build());


        opts.addOption(Option.builder("n")
                .longOpt("hostName")
                .hasArg(true)
                .argName("hostName")
                .desc("Host name override for the destination filename prefix.")
                .required(false)
                .build());

        

        this.cmds.addCommand("Log utilities", "log:rename", opts,
                "Rename and relocate collected log files.",
                (CommandLine cl) -> {
                    Path srcPath = Path.of(cl.getOptionValue("srcDir"));
                    Path destPath = Path.of(cl.getOptionValue("destDir"));
                    String hostName = cl.getOptionValue("hostName", LogRenamer.hostName());
                    LogRenamer renamer = new LogRenamer();
                    renamer.rename(hostName, srcPath, destPath);
                });
        
    }

    /**
     * Registers the {@code ubuntu:report} command that exports Ubuntu Security Notices.
     */
    public void ubuntuSecurityReportCommand() {
        Options opts = new Options();

        opts.addOption(Option.builder("infile")
                .option("i")
                .longOpt("infile")
                .hasArg(true)
                .argName("infile")
                .desc("An input file of ubuntu security report.")
                .required(true)
                .build());

        opts.addOption(Option.builder("format")
                .option("f")
                .longOpt("format")
                .hasArg(true)
                .argName("format")
                .desc("The format of the report (tsv or json)")
                .required(false)
                .build());


        this.cmds.addCommand("Ubuntu security commands", "ubuntu:report", opts,
                "Create TSV format report.",
                (CommandLine cl) -> {
                    Path infilePath = Path.of(cl.getOptionValue("infile"));
                    String format = cl.getOptionValue("format", "tsv");
                    USNJsonExporter exporter = new USNJsonExporter();
                    exporter.report(infilePath, format);
                });
    }

    /**
     * Registers the {@code ubuntu:fetch-digest} command that downloads digest emails from Gmail.
     */
    public void gmailDigestFetchCommand() {
        Options opts = new Options();

        opts.addOption(Option.builder("S")
                .longOpt("start")
                .hasArg(true)
                .argName("YYYY-MM-DD")
                .desc("Start date (inclusive) for fetching digests. ISO format.")
                .required(true)
                .build());

        opts.addOption(Option.builder("E")
                .longOpt("end")
                .hasArg(true)
                .argName("YYYY-MM-DD")
                .desc("End date (inclusive) for fetching digests. ISO format.")
                .required(true)
                .build());

        opts.addOption(Option.builder("o")
                .longOpt("outfile")
                .hasArg(true)
                .argName("file")
                .desc("Output file path for the concatenated digest text.")
                .required(true)
                .build());

        this.cmds.addCommand("Ubuntu security commands", "ubuntu:fetch-digest", opts,
                "Fetch ubuntu-security-announce digests from Gmail within the date range.",
                (CommandLine cl) -> {
                    DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE;
                    LocalDate startDate;
                    LocalDate endDate;
                    try {
                        startDate = LocalDate.parse(cl.getOptionValue("start"), formatter);
                    } catch (DateTimeParseException e) {
                        System.err.println("Invalid --start date. Use YYYY-MM-DD.");
                        return;
                    }

                    try {
                        endDate = LocalDate.parse(cl.getOptionValue("end"), formatter);
                    } catch (DateTimeParseException e) {
                        System.err.println("Invalid --end date. Use YYYY-MM-DD.");
                        return;
                    }

                    if (endDate.isBefore(startDate)) {
                        System.err.println("--end date must be the same as or after --start date.");
                        return;
                    }

                    Path output = Path.of(cl.getOptionValue("outfile"));
                    String username = System.getenv("GMAIL_USERNAME");
                    String password = System.getenv("GMAIL_APP_PASSWORD");

                    if (username == null || username.isBlank()) {
                        System.err.println("Environment variable GMAIL_USERNAME is not set.");
                        return;
                    }

                    if (password == null || password.isBlank()) {
                        System.err.println("Environment variable GMAIL_APP_PASSWORD is not set.");
                        return;
                    }

                    try {
                        GmailIMAPFetcher.fetchAndSave(startDate, endDate, output, username, password);
                        System.out.println("Saved ubuntu-security-announce digests to: " + output);
                    } catch (MessagingException | IOException e) {
                        System.err.println("Failed to fetch digests: " + e.getMessage());
                    }
                });
    }


}
