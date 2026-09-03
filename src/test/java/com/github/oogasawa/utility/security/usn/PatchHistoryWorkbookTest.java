package com.github.oogasawa.utility.security.usn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.VerticalAlignment;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFColor;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Unit tests for {@link PatchHistoryWorkbook}.
 *
 * <p>
 * These tests touch no external service. Each test builds a small workbook of the same shape as the
 * patch history record, in a directory that JUnit creates and removes.
 * </p>
 */
@DisplayName("PatchHistoryWorkbook — adding a report to the patch history record")
public class PatchHistoryWorkbookTest {

    @TempDir
    Path tempDir;

    private static final String REPORT = """
            id\ttitle\tpublished_date\tsummary\tseverity\treboot\tlivepatch
            USN-8700-1\tVim vulnerability\t2026-08-30\tVim could be made to crash.\tMedium\tno\tNA
            USN-8701-1\tLinux kernel vulnerabilities\t2026-08-31\tSeveral issues were fixed.\tHigh\tyes\tno
            """;

    /** Writes a workbook that holds one sheet with a header and one recorded notice. */
    private Path writeSourceWorkbook(String sheetName, String recordedNoticeId) throws IOException {
        Path file = this.tempDir.resolve("source.xlsx");
        try (Workbook workbook = new XSSFWorkbook()) {
            Sheet sheet = workbook.createSheet(sheetName);
            Row header = sheet.createRow(0);
            String[] headers = {"", "title", "published_date", "summary", "severity", "reboot",
                    "livepatch", "対策内容 (GW, dtn)"};
            for (int i = 0; i < headers.length; i++) {
                header.createCell(i).setCellValue(headers[i]);
            }
            Row row = sheet.createRow(1);
            row.createCell(0).setCellValue(recordedNoticeId);
            row.createCell(1).setCellValue("Already recorded");
            row.createCell(7).setCellValue("〇");

            try (OutputStream out = Files.newOutputStream(file)) {
                workbook.write(out);
            }
        }
        return file;
    }

    private Path writeReport() throws IOException {
        Path file = this.tempDir.resolve("report.tsv");
        Files.writeString(file, REPORT, StandardCharsets.UTF_8);
        return file;
    }

    private static List<String> firstColumnOf(Sheet sheet) {
        return java.util.stream.StreamSupport.stream(sheet.spliterator(), false)
                .map(row -> row.getCell(0))
                .map(cell -> cell == null ? "" : cell.getStringCellValue())
                .toList();
    }

    @Test
    @DisplayName("A sheet that does not exist is created with the same header as the record")
    void addReport_sheetAbsent_createsItWithTheHeader() throws IOException {
        Path source = writeSourceWorkbook("2025", "USN-7520-1");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            Sheet sheet = workbook.getSheet("2026");
            assertNotNull(sheet);
            Row header = sheet.getRow(0);
            assertEquals("title", header.getCell(1).getStringCellValue());
            assertEquals("livepatch", header.getCell(6).getStringCellValue());
            assertEquals("severe_cves", header.getCell(7).getStringCellValue());
            assertEquals("備考", header.getCell(16).getStringCellValue());
        }
    }

    @Test
    @DisplayName("Every notice of the report is written to the sheet")
    void addReport_report_writesEveryNotice() throws IOException {
        Path source = writeSourceWorkbook("2025", "USN-7520-1");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            Sheet sheet = workbook.getSheet("2026");
            assertIterableEquals(List.of("", "USN-8700-1", "USN-8701-1"), firstColumnOf(sheet));

            Row row = sheet.getRow(2);
            assertEquals("Linux kernel vulnerabilities", row.getCell(1).getStringCellValue());
            assertEquals("2026-08-31", row.getCell(2).getStringCellValue());
            assertEquals("High", row.getCell(4).getStringCellValue());
            assertEquals("yes", row.getCell(5).getStringCellValue());
            assertEquals("no", row.getCell(6).getStringCellValue());
        }
    }

    @Test
    @DisplayName("The columns that people fill in hold no value")
    void addReport_report_leavesTheColumnsForPeopleEmpty() throws IOException {
        Path source = writeSourceWorkbook("2025", "USN-7520-1");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            Row row = workbook.getSheet("2026").getRow(1);
            for (int column = 8; column <= 16; column++) {
                assertEquals("", row.getCell(column).getStringCellValue(), "column " + column);
            }
        }
    }

    @Test
    @DisplayName("A notice already in the record is not written again")
    void addReport_noticeAlreadyRecorded_isNotWrittenAgain() throws IOException {
        Path source = writeSourceWorkbook("2025", "USN-8700-1");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            assertIterableEquals(List.of("", "USN-8701-1"),
                    firstColumnOf(workbook.getSheet("2026")));
        }
    }

    @Test
    @DisplayName("Running twice adds nothing the second time")
    void addReport_runTwice_addsNothingTheSecondTime() throws IOException {
        Path source = writeSourceWorkbook("2025", "USN-7520-1");
        Path first = this.tempDir.resolve("first.xlsx");
        Path second = this.tempDir.resolve("second.xlsx");
        Path report = writeReport();

        new PatchHistoryWorkbook().addReport(source, report, first, "2026");
        new PatchHistoryWorkbook().addReport(first, report, second, "2026");

        try (InputStream in = Files.newInputStream(second);
                Workbook workbook = new XSSFWorkbook(in)) {
            assertIterableEquals(List.of("", "USN-8700-1", "USN-8701-1"),
                    firstColumnOf(workbook.getSheet("2026")));
        }
    }

    @Test
    @DisplayName("The source workbook is left byte for byte unchanged")
    void addReport_anyReport_leavesTheSourceWorkbookUnchanged() throws IOException {
        Path source = writeSourceWorkbook("2025", "USN-7520-1");
        byte[] before = Files.readAllBytes(source);

        new PatchHistoryWorkbook().addReport(source, writeReport(),
                this.tempDir.resolve("output.xlsx"), "2026");

        assertArrayEquals(before, Files.readAllBytes(source));
    }

    @Test
    @DisplayName("An existing sheet receives the new rows after the rows already there")
    void addReport_sheetAlreadyPresent_appendsAfterTheExistingRows() throws IOException {
        Path source = writeSourceWorkbook("2026", "USN-7520-1");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            assertIterableEquals(List.of("", "USN-7520-1", "USN-8700-1", "USN-8701-1"),
                    firstColumnOf(workbook.getSheet("2026")));
        }
    }

    @Test
    @DisplayName("The header line of the report is not written as a row")
    void readReport_report_dropsTheHeaderLine() throws IOException {
        List<List<String>> rows = PatchHistoryWorkbook.readReport(writeReport(), 8);

        assertEquals(2, rows.size());
        assertEquals("USN-8700-1", rows.get(0).get(0));
        assertEquals(8, rows.get(0).size());
    }

    @Test
    @DisplayName("A new sheet is given the column widths and the frozen heading of the record")
    void addReport_newSheet_isGivenTheFormattingOfTheRecord() throws IOException {
        Path source = writeSourceWorkbook("2025", "USN-7520-1");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            Sheet sheet = workbook.getSheet("2026");
            assertEquals(1, sheet.getPaneInformation().getHorizontalSplitPosition());
            assertEquals((int) (12.71 * 256), sheet.getColumnWidth(0));
            assertEquals((int) (45.57 * 256), sheet.getColumnWidth(3));
        }
    }

    @Test
    @DisplayName("Every cell is aligned to the top and wraps its text")
    void addReport_everyCell_isTopAlignedAndWrapped() throws IOException {
        Path source = writeSourceWorkbook("2025", "USN-7520-1");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            Sheet sheet = workbook.getSheet("2026");
            for (Row row : sheet) {
                for (int column = 0; column <= 16; column++) {
                    Cell cell = row.getCell(column);
                    String where = "row " + row.getRowNum() + " column " + column;
                    assertEquals(VerticalAlignment.TOP, cell.getCellStyle().getVerticalAlignment(),
                            where);
                    assertTrue(cell.getCellStyle().getWrapText(), where);
                }
            }
        }
    }

    @Test
    @DisplayName("The heading of a new sheet carries the colours of the record")
    void addReport_newSheet_headingCarriesTheColours() throws IOException {
        Path source = writeSourceWorkbook("2025", "USN-7520-1");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            Row header = workbook.getSheet("2026").getRow(0);
            XSSFColor report =
                    (XSSFColor) header.getCell(0).getCellStyle().getFillForegroundColorColor();
            XSSFColor manual =
                    (XSSFColor) header.getCell(8).getCellStyle().getFillForegroundColorColor();
            assertEquals("93C47D", report.getARGBHex().substring(2));
            assertEquals("FCE5CD", manual.getARGBHex().substring(2));
        }
    }
}
