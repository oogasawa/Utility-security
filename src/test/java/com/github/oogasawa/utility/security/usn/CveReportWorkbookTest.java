package com.github.oogasawa.utility.security.usn;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class CveReportWorkbookTest {

    private static final String TSV = "id\tcategory\tcve\tpublished_date\ttarget\tseverity\tcvss\tfixed\tsummary\n"
            + "FG-IR-26-182\tFortiGate\tCVE-2026-106175\t2026-10-13\tFortiOS 7.4.6: 該当\tLOW\t2.1\tmigrate\tDouble free\n"
            + "GHSA-xxxx\tJava\tCVE-2099-1\t2026-01-01\tg:a:1 (proj)\tHIGH\t\t2\tBad\n";

    @Test
    void addsRowsOnceAndKeepsWhatPeopleWrote(@TempDir Path dir) throws Exception {
        Path source = dir.resolve("source.xlsx");
        try (Workbook wb = new XSSFWorkbook(); OutputStream out = Files.newOutputStream(source)) {
            wb.createSheet("2026");
            wb.write(out);
        }
        Path tsv = dir.resolve("report.tsv");
        Files.writeString(tsv, TSV);

        Path first = dir.resolve("first.xlsx");
        new PatchHistoryWorkbook().addCveReport(source, tsv, first, "usn以外のcve");

        // A person writes in the first manual column of the first row.
        Path edited = dir.resolve("edited.xlsx");
        try (var in = Files.newInputStream(first); Workbook wb = new XSSFWorkbook(in);
                OutputStream out = Files.newOutputStream(edited)) {
            Sheet sheet = wb.getSheet("usn以外のcve");
            assertEquals("GHSA-xxxx", sheet.getRow(1).getCell(0).getStringCellValue());
            sheet.getRow(2).createCell(9).setCellValue("patched");
            wb.write(out);
        }

        Path second = dir.resolve("second.xlsx");
        new PatchHistoryWorkbook().addCveReport(edited, tsv, second, "usn以外のcve");

        try (var in = Files.newInputStream(second); Workbook wb = new XSSFWorkbook(in)) {
            Sheet sheet = wb.getSheet("usn以外のcve");
            assertEquals(3, sheet.getPhysicalNumberOfRows());
            // Oldest first, and what the person wrote moved with its row.
            assertEquals("GHSA-xxxx", sheet.getRow(1).getCell(0).getStringCellValue());
            assertEquals("FG-IR-26-182", sheet.getRow(2).getCell(0).getStringCellValue());
            assertEquals("patched", sheet.getRow(2).getCell(9).getStringCellValue());
            assertEquals(2, wb.getNumberOfSheets());
        }
    }

    @Test
    void anAdvisoryAlreadyRecordedGetsItsNewTargetInsteadOfASecondRow(@TempDir Path dir)
            throws Exception {
        Path source = dir.resolve("source.xlsx");
        try (Workbook wb = new XSSFWorkbook(); OutputStream out = Files.newOutputStream(source)) {
            wb.createSheet("2026");
            wb.write(out);
        }
        String header = "id\tcategory\tcve\tpublished_date\ttarget\tseverity\tcvss\tfixed\tsummary\n";
        Path before = dir.resolve("before.tsv");
        Files.writeString(before, header + "GHSA-a\tJava\tCVE-1\t2026-03-26\tlib 1 (p1)\tHIGH\t\t2\tBad\n");
        Path after = dir.resolve("after.tsv");
        Files.writeString(after, header + "GHSA-a\tJava\tCVE-1\t2026-03-26\tlib 1 (p1, p2)\tHIGH\t\t2\tBad\n");

        Path first = dir.resolve("first.xlsx");
        new PatchHistoryWorkbook().addCveReport(source, before, first, "usn以外のcve");
        Path second = dir.resolve("second.xlsx");
        new PatchHistoryWorkbook().addCveReport(first, after, second, "usn以外のcve");

        try (var in = Files.newInputStream(second); Workbook wb = new XSSFWorkbook(in)) {
            Sheet sheet = wb.getSheet("usn以外のcve");
            assertEquals(2, sheet.getPhysicalNumberOfRows());
            assertEquals("lib 1 (p1, p2)", sheet.getRow(1).getCell(4).getStringCellValue());
        }
    }
}
