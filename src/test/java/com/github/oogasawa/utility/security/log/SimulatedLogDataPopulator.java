package com.github.oogasawa.utility.security.log;

import java.io.IOException;
import java.nio.file.*;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;

/**
 * Populates a test directory with a structure and file set identical to a real /var/log.
 */
public class SimulatedLogDataPopulator {


    static List<SrcAndDest> TEST_FILE_NAMES = Arrays.asList(
            new SrcAndDest("alternatives.log", null), new SrcAndDest("apache2/access.log", null),
            new SrcAndDest("apache2/access.log.1", null),
            new SrcAndDest("apache2/access.log-20250610.gz",
                    "apache2/access.log-20250610_testServer.gz"),
            new SrcAndDest("apache2/access.log-20250622", "apache2/access.log-20250622_testServer"),
            new SrcAndDest("apache2/error.log", null), new SrcAndDest("apache2/error.log.1", null),
            new SrcAndDest("apache2/error.log-20250610.gz",
                    "apache2/error.log-20250610_testServer.gz"),
            new SrcAndDest("apache2/error.log-20250622", "apache2/error.log-20250622_testServer"),
            new SrcAndDest("apache2/other_vhosts_access.log", null),
            new SrcAndDest("apache2/sc.ddbj.nig.ac.jp-access.log", null),
            new SrcAndDest("apache2/sc.ddbj.nig.ac.jp-access.log.1", null),
            new SrcAndDest("sc.ddbj.nig.ac.jp-error.log", null),
            new SrcAndDest("sc.ddbj.nig.ac.jp-error.log.1", null),
            new SrcAndDest("apport.log", null), new SrcAndDest("apt/eipp.log.xz", null),
            new SrcAndDest("apt/history.log", null), new SrcAndDest("apt/term.log", null),
            new SrcAndDest("auth.log", null), new SrcAndDest("auth.log-20250615_testServer", null),
            new SrcAndDest("auth.log-20250622", "auth.log-20250622_testServer"),
            new SrcAndDest("btmp", null), new SrcAndDest("btmp", null),
            new SrcAndDest("dist-upgrade", null), new SrcAndDest("dmesg", null),
            new SrcAndDest("dmesg.0", null), new SrcAndDest("dmesg.1.gz", null),
            new SrcAndDest("dmesg.2.gz", null), new SrcAndDest("dmesg.3.gz", null),
            new SrcAndDest("dpkg.log", null), new SrcAndDest("installer", null),
            new SrcAndDest(
                    "journal/741efd1e8ead45a6b9617a7f4e0decb8/system@201fd858ffad44c69c52e9bdd721acba-0000000000003768-000637184f01c80c.journal",
                    null),
            new SrcAndDest(
                    "journal/741efd1e8ead45a6b9617a7f4e0decb8/system@64f1a15159454fea9d8d69f3f4f2f74b-000000000000027f-000636fc284a2363.journal",
                    null),
            new SrcAndDest(
                    "journal/741efd1e8ead45a6b9617a7f4e0decb8/system@daa0ae0170934588acbf17e4aab5fde0-0000000000002d80-0006371474c95d31.journal",
                    null),
            new SrcAndDest(
                    "journal/741efd1e8ead45a6b9617a7f4e0decb8/system@daa0ae0170934588acbf17e4aab5fde0-0000000000003132-000637147adcec27.journal",
                    null),
            new SrcAndDest(
                    "journal/741efd1e8ead45a6b9617a7f4e0decb8/system@eda943532489449798ca79e4e21b7fe2-0000000000000957-000636fc55e8d6f6.journal",
                    null),
            new SrcAndDest(
                    "journal/741efd1e8ead45a6b9617a7f4e0decb8/system@eda943532489449798ca79e4e21b7fe2-0000000000000cb9-000636fc5b3c5ce2.journal",
                    null),
            new SrcAndDest("journal/741efd1e8ead45a6b9617a7f4e0decb8/system.journal", null),
            new SrcAndDest(
                    "journal/741efd1e8ead45a6b9617a7f4e0decb8/user-1000@64f1a15159454fea9d8d69f3f4f2f74b-0000000000000651-000636fc2f3bb820.journal",
                    null),
            new SrcAndDest(
                    "journal/741efd1e8ead45a6b9617a7f4e0decb8/user-1000@eda943532489449798ca79e4e21b7fe2-0000000000000cb8-000636fc5b3a0088.journal",
                    null),
            new SrcAndDest(
                    "journal/741efd1e8ead45a6b9617a7f4e0decb8/user-1001@daa0ae0170934588acbf17e4aab5fde0-0000000000003131-000637147ad9b27c.journal",
                    null),
            new SrcAndDest(
                    "journal/741efd1e8ead45a6b9617a7f4e0decb8/user-1001@eda943532489449798ca79e4e21b7fe2-0000000000000e96-000636fd3c6d188b.journal",
                    null),
            new SrcAndDest("journal/741efd1e8ead45a6b9617a7f4e0decb8/user-1001.journal", null),
            new SrcAndDest("journal/741efd1e8ead45a6b9617a7f4e0decb8/user-1002.journal", null),

            // journal-exportについてはログローテートが間違っている
            new SrcAndDest("journal-export/journal-20250608.log",
                    "journal-export/journal-20250608_testServer.log"),
            new SrcAndDest("journal-export/journal-20250608.log.1.gz",
                    "journal-export/journal-20250608.log.1.gz"),
            new SrcAndDest("journal-export/journal-20250609.log", null),
            new SrcAndDest("journal-export/journal-20250609.log.1.gz", null),
            new SrcAndDest("journal-export/journal-20250610.log", null),
            new SrcAndDest("journal-export/journal-20250610.log.1.gz", null),
            new SrcAndDest("journal-export/journal-20250611.log", null),
            new SrcAndDest("journal-export/journal-20250611.log.1.gz", null),
            new SrcAndDest("journal-export/journal-20250612.log", null),
            new SrcAndDest("journal-export/journal-20250612.log.1.gz", null),
            new SrcAndDest("journal-export/journal-20250613.log", null),
            new SrcAndDest("journal-export/journal-20250613.log.1.gz", null),
            new SrcAndDest("journal-export/journal-20250614.log", null),
            new SrcAndDest("journal-export/journal-20250614.log.1.gz", null),
            new SrcAndDest("journal-export/journal-20250615.log", null),
            new SrcAndDest("journal-export/journal-20250615.log.1.gz", null),
            new SrcAndDest("journal-export/journal-20250616.log", null),
            new SrcAndDest("journal-export/journal-20250616.log.1.gz", null),
            new SrcAndDest("journal-export/journal-20250617.log", null),
            new SrcAndDest("journal-export/journal-20250617.log.1.gz", null),
            new SrcAndDest("journal-export/journal-20250618.log", null),
            new SrcAndDest("journal-export/journal-20250618.log.1.gz", null),
            new SrcAndDest("journal-export/journal-20250619.log", null),
            new SrcAndDest("journal-export/journal-20250619.log.1.gz", null),
            new SrcAndDest("journal-export/journal-20250620.log", null),

            new SrcAndDest("kern.log", null), new SrcAndDest("kern.log-20250615_testServer", null),
            new SrcAndDest("kern.log-20250622", "kern.log-20250622_testServer"),
            new SrcAndDest("landscape/sysinfo.log", null), new SrcAndDest("lastlog", null),
            new SrcAndDest("private", null), new SrcAndDest("README", null),
            new SrcAndDest("syslog", null),
            new SrcAndDest("syslog-20250615.gz", "syslog-20250615_testServer.gz"),
            new SrcAndDest("syslog-20250622", null), new SrcAndDest("sysstat/sa14", null),
            new SrcAndDest("sysstat/sa15", null), new SrcAndDest("sysstat/sa16", null),
            new SrcAndDest("sysstat/sa17", null), new SrcAndDest("sysstat/sa18", null),
            new SrcAndDest("sysstat/sa19", null), new SrcAndDest("sysstat/sa20", null),
            new SrcAndDest("sysstat/sa21", null), new SrcAndDest("sysstat/sa22", null),
            new SrcAndDest("sysstat/sar14", null), new SrcAndDest("sysstat/sar15", null),
            new SrcAndDest("sysstat/sar16", null), new SrcAndDest("sysstat/sar17", null),
            new SrcAndDest("sysstat/sar18", null), new SrcAndDest("sysstat/sar19", null),
            new SrcAndDest("sysstat/sar20", null), new SrcAndDest("sysstat/sar21", null),
            new SrcAndDest("ubuntu-advantage.log", null), new SrcAndDest("ufw.log", null),
            new SrcAndDest("ufw.log-20250615_testServer", null),
            new SrcAndDest("ufw.log-20250622", "ufw.log-20250622_testServer"),
            new SrcAndDest("unattended-upgrades/unattended-upgrades-dpkg.log", null),
            new SrcAndDest("unattended-upgrades/unattended-upgrades.log", null),
            new SrcAndDest("unattended-upgrades/unattended-upgrades-shutdown.log", null),
            new SrcAndDest("wtmp", null)

    );


    
    public static void populate(Path baseDir) throws IOException {
        // apache2
        Path apache2 = baseDir.resolve("apache2");
        Files.createDirectories(apache2);
        writeAll(apache2, "access.log", "access.log.1", "access.log-20250622",
                "error.log", "error.log.1", "error.log-20250622",
                "other_vhosts_access.log",
                "sc.ddbj.nig.ac.jp-access.log", "sc.ddbj.nig.ac.jp-access.log.1",
                "sc.ddbj.nig.ac.jp-error.log", "sc.ddbj.nig.ac.jp-error.log.1");
        writeDailyLogs(apache2, "access.log", true);
        writeDailyLogs(apache2, "error.log", true);

        // apt
        Path apt = baseDir.resolve("apt");
        Files.createDirectories(apt);
        writeAll(apt, "eipp.log.xz", "history.log", "term.log");

        // journal
        Path journal = baseDir.resolve("journal/741efd1e8ead45a6b9617a7f4e0decb8");
        Files.createDirectories(journal);
        writeAll(journal,
                "system@201fd858ffad44c69c52e9bdd721acba-0000000000003768-000637184f01c80c.journal",
                "system@64f1a15159454fea9d8d69f3f4f2f74b-000000000000027f-000636fc284a2363.journal",
                "system@daa0ae0170934588acbf17e4aab5fde0-0000000000002d80-0006371474c95d31.journal",
                "system@daa0ae0170934588acbf17e4aab5fde0-0000000000003132-000637147adcec27.journal",
                "system@eda943532489449798ca79e4e21b7fe2-0000000000000957-000636fc55e8d6f6.journal",
                "system@eda943532489449798ca79e4e21b7fe2-0000000000000cb9-000636fc5b3c5ce2.journal",
                "system.journal",
                "user-1000@64f1a15159454fea9d8d69f3f4f2f74b-0000000000000651-000636fc2f3bb820.journal",
                "user-1000@eda943532489449798ca79e4e21b7fe2-0000000000000cb8-000636fc5b3a0088.journal",
                "user-1001@daa0ae0170934588acbf17e4aab5fde0-0000000000003131-000637147ad9b27c.journal",
                "user-1001@eda943532489449798ca79e4e21b7fe2-0000000000000e96-000636fd3c6d188b.journal",
                "user-1001.journal", "user-1002.journal");

        // journal-export
        Path jexport = baseDir.resolve("journal-export");
        Files.createDirectories(jexport);
        IntStream.rangeClosed(8, 20).forEach(day -> {
            try {
                String base = String.format("journal-202506%02d.log", day);
                writeAll(jexport, base, base + ".1.gz");
            } catch (IOException e) { throw new RuntimeException(e); }
        });

        // sysstat
        Path sysstat = baseDir.resolve("sysstat");
        Files.createDirectories(sysstat);
        IntStream.rangeClosed(14, 22).forEach(day -> {
            try {
                writeAll(sysstat, "sa" + day, "sar" + day);
            } catch (IOException e) { throw new RuntimeException(e); }
        });

        // unattended-upgrades
        Path unattended = baseDir.resolve("unattended-upgrades");
        Files.createDirectories(unattended);
        writeAll(unattended, "unattended-upgrades-dpkg.log", "unattended-upgrades.log", "unattended-upgrades-shutdown.log");

        // top-level files and dirs
        writeAll(baseDir, "alternatives.log", "apport.log", "auth.log", "auth.log-20250615_testServer",
                "auth.log-20250622", "btmp", "dmesg", "dmesg.0", "dmesg.1.gz", "dmesg.2.gz", "dmesg.3.gz",
                "dpkg.log", "kern.log", "kern.log-20250615_testServer", "kern.log-20250622",
                "syslog", "syslog-20250615.gz", "syslog-20250622", "ufw.log", "ufw.log-20250615_testServer",
                "ufw.log-20250622", "ubuntu-advantage.log", "wtmp");

        Files.createDirectories(baseDir.resolve("dist-upgrade"));
        Files.createDirectories(baseDir.resolve("installer"));
        Files.createDirectories(baseDir.resolve("landscape"));
        Files.writeString(baseDir.resolve("README"), "README -> ../../usr/share/doc/systemd/README.logs");
        Files.createDirectories(baseDir.resolve("private"));
    }

    private static void writeAll(Path dir, String... names) throws IOException {
        for (String name : names) {
            Files.write(dir.resolve(name), ("dummy content for " + name).getBytes());
        }
    }

    private static void writeDailyLogs(Path dir, String prefix, boolean gzipped) throws IOException {
        IntStream.rangeClosed(10, 21).forEach(day -> {
            try {
                String name = prefix + "-202506" + String.format("%02d", day);
                if (gzipped) name += ".gz";
                writeAll(dir, name);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }
}
