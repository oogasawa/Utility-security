package com.github.oogasawa.utility.security;


import java.nio.file.Path;
import com.github.oogasawa.utility.cli.CommandRepository;
import com.github.oogasawa.utility.security.log.LogRenamer;
import com.github.oogasawa.utility.security.usn.USNJsonExporter;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;


public class App {

    /**
     * The command-line usage synopsis.
     */
    String synopsis = "java -jar your_program-<VERSION>-fat.jar <command> <options>";
    
    /**
     * The repository that holds command definitions and executes them.
     */
    CommandRepository cmds = new CommandRepository();

    /**
     * The main method initializes the application and processes command-line input.
     * 
     * @param args the command-line arguments
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
        
    }
    


    public void logRenameCommand() {
        Options opts = new Options();

        opts.addOption(Option.builder("srcDir")
                .option("s")
                .longOpt("srcDir")
                .hasArg(true)
                .argName("srcDir")
                .desc("The source directory of the log files.")
                .required(true)
                .build());

        opts.addOption(Option.builder("destDir")
                .option("d")
                .longOpt("destDir")
                .hasArg(true)
                .argName("destDir")
                .desc("The destination directory of the log files.")
                .required(true)
                .build());


        opts.addOption(Option.builder("hostName")
                .option("n")
                .longOpt("hostName")
                .hasArg(true)
                .argName("hostName")
                .desc("host name")
                .required(false)
                .build());

        

        this.cmds.addCommand("Ubuntu security commands", "ubuntu:report", opts,
                "Create TSV format report.",
                (CommandLine cl) -> {
                    Path srcPath = Path.of(cl.getOptionValue("srcPath"));
                    Path destPath = Path.of(cl.getOptionValue("destPath"));
                    String hostName = cl.getOptionValue("hostName",LogRenamer.hostName());
                    LogRenamer renamer = new LogRenamer();
                    renamer.rename(hostName, srcPath, destPath);
                });
        
    }



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

    

}
