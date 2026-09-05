package com.github.oogasawa.utility.security.usn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

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
    @DisplayName("A notice already recorded under another suffix is not written again")
    void addReport_noticeRecordedUnderAnotherSuffix_isNotWrittenAgain() throws IOException {
        // The record holds USN-8700-3, and a later run names the same group USN-8700-1 because an
        // issue published earlier came into the list.
        Path source = writeSourceWorkbook("2026", "USN-8700-3");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            assertIterableEquals(List.of("", "USN-8700-3", "USN-8701-1"),
                    firstColumnOf(workbook.getSheet("2026")));
        }
    }

    @Test
    @DisplayName("A row recorded under another suffix is given the severity a later run retrieved")
    void addReport_rowAwaitingARankUnderAnotherSuffix_isGivenTheSeverity() throws IOException {
        Path source = writeWorkbookWithARowAwaitingARank("USN-8700-3", "対応済み");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            Sheet sheet = workbook.getSheet("2026");
            assertIterableEquals(List.of("", "USN-8700-1", "USN-8701-1"), firstColumnOf(sheet));
            assertEquals("Medium", sheet.getRow(1).getCell(4).getStringCellValue());
            assertEquals("対応済み", sheet.getRow(1).getCell(16).getStringCellValue());
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

    /**
     * Writes a workbook whose sheet holds a notice recorded while the priority could not be
     * retrieved, together with a note that a person wrote in the last column.
     */
    private Path writeWorkbookWithARowAwaitingARank(String noticeId, String note)
            throws IOException {
        Path file = this.tempDir.resolve("awaiting.xlsx");
        try (Workbook workbook = new XSSFWorkbook()) {
            Sheet sheet = workbook.createSheet("2026");
            sheet.createRow(0).createCell(0).setCellValue("");
            Row row = sheet.createRow(1);
            row.createCell(0).setCellValue(noticeId);
            row.createCell(1).setCellValue("Vim vulnerability");
            row.createCell(2).setCellValue("2026-08-30");
            row.createCell(3).setCellValue("Vim could be made to crash.");
            row.createCell(4).setCellValue("LookupFailed");
            row.createCell(5).setCellValue("no");
            row.createCell(6).setCellValue("NA");
            row.createCell(16).setCellValue(note);

            try (OutputStream out = Files.newOutputStream(file)) {
                workbook.write(out);
            }
        }
        return file;
    }

    @Test
    @DisplayName("A row recorded as LookupFailed is given the severity a later run retrieved")
    void addReport_rowAwaitingARank_isGivenTheSeverity() throws IOException {
        Path source = writeWorkbookWithARowAwaitingARank("USN-8700-1", "対応済み");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            Sheet sheet = workbook.getSheet("2026");
            assertIterableEquals(List.of("", "USN-8700-1", "USN-8701-1"), firstColumnOf(sheet));
            assertEquals("Medium", sheet.getRow(1).getCell(4).getStringCellValue());
        }
    }

    @Test
    @DisplayName("Writing over a row keeps what a person wrote in it")
    void addReport_rowAwaitingARank_keepsWhatAPersonWrote() throws IOException {
        Path source = writeWorkbookWithARowAwaitingARank("USN-8700-1", "対応済み");
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            assertEquals("対応済み",
                    workbook.getSheet("2026").getRow(1).getCell(16).getStringCellValue());
        }
    }

    @Test
    @DisplayName("A row recorded as LookupFailed is left alone when the run failed as well")
    void addReport_lookupFailedAgain_leavesTheRowAlone() throws IOException {
        Path source = writeWorkbookWithARowAwaitingARank("USN-8700-1", "対応済み");
        Path report = this.tempDir.resolve("failed.tsv");
        Files.writeString(report, REPORT.replace("\tMedium\t", "\tLookupFailed\t"),
                StandardCharsets.UTF_8);
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, report, output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            Sheet sheet = workbook.getSheet("2026");
            assertIterableEquals(List.of("", "USN-8700-1", "USN-8701-1"), firstColumnOf(sheet));
            assertEquals("LookupFailed", sheet.getRow(1).getCell(4).getStringCellValue());
        }
    }

    @Test
    @DisplayName("A row carrying a severity is never written over")
    void addReport_rowCarryingASeverity_isNeverWrittenOver() throws IOException {
        Path source = writeWorkbookWithARowAwaitingARank("USN-8700-1", "対応済み");
        Path first = this.tempDir.resolve("first.xlsx");
        Path second = this.tempDir.resolve("second.xlsx");
        Path report = this.tempDir.resolve("changed.tsv");
        Files.writeString(report, REPORT.replace("\tMedium\t", "\tLow\t"),
                StandardCharsets.UTF_8);

        new PatchHistoryWorkbook().addReport(source, writeReport(), first, "2026");
        new PatchHistoryWorkbook().addReport(first, report, second, "2026");

        try (InputStream in = Files.newInputStream(second);
                Workbook workbook = new XSSFWorkbook(in)) {
            assertEquals("Medium",
                    workbook.getSheet("2026").getRow(1).getCell(4).getStringCellValue());
        }
    }

    /**
     * Rewrites one file inside a workbook, which is a zip archive holding one file per sheet.
     *
     * @param workbook the workbook to change
     * @param entryName the file inside it
     * @param change what to do to the text of that file
     */
    private void rewriteInside(Path workbook, String entryName,
            java.util.function.UnaryOperator<String> change) throws IOException {
        Path rewritten = this.tempDir.resolve("rewritten.xlsx");
        try (ZipFile source = new ZipFile(workbook.toFile());
                ZipOutputStream out =
                        new ZipOutputStream(Files.newOutputStream(rewritten))) {
            for (ZipEntry entry : java.util.Collections.list(source.entries())) {
                out.putNextEntry(new ZipEntry(entry.getName()));
                byte[] content = source.getInputStream(entry).readAllBytes();
                if (entry.getName().equals(entryName)) {
                    content = change.apply(new String(content, StandardCharsets.UTF_8))
                            .getBytes(StandardCharsets.UTF_8);
                }
                out.write(content);
                out.closeEntry();
            }
        }
        Files.move(rewritten, workbook, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    /** The text of one file inside a workbook. */
    private static String textInside(Path workbook, String entryName) throws IOException {
        try (ZipFile archive = new ZipFile(workbook.toFile())) {
            return new String(archive.getInputStream(archive.getEntry(entryName)).readAllBytes(),
                    StandardCharsets.UTF_8);
        }
    }

    @Test
    @DisplayName("A cell whose text sits in the cell itself carries only the new value")
    void addReport_cellHoldingAnInlineString_carriesOnlyTheNewValue() throws IOException {
        Path source = writeWorkbookWithARowAwaitingARank("USN-8700-1", "対応済み");
        // Some spreadsheet programs keep the text of a cell in the cell itself rather than in the
        // table of shared text. Put the severity in that shape, the way one of them would leave
        // it, so that the cell says LookupFailed in two places at once.
        rewriteInside(source, "xl/worksheets/sheet1.xml",
                xml -> xml.replaceFirst("<c r=\"E2\"[^>]*>.*?</c>",
                        "<c r=\"E2\" t=\"inlineStr\"><is><t>LookupFailed</t></is>"
                                + "<v>LookupFailed</v></c>"));
        Path output = this.tempDir.resolve("output.xlsx");

        new PatchHistoryWorkbook().addReport(source, writeReport(), output, "2026");

        try (InputStream in = Files.newInputStream(output);
                Workbook workbook = new XSSFWorkbook(in)) {
            assertEquals("Medium",
                    workbook.getSheet("2026").getRow(1).getCell(4).getStringCellValue());
        }
        // The table of shared text keeps entries no cell refers to any more, so the old text
        // may still be there. What must be gone is the copy sitting in the cell.
        assertFalse(textInside(output, "xl/worksheets/sheet1.xml").contains("LookupFailed"),
                "the text the cell used to hold is still in the cell");
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
