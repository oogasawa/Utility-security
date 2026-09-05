package com.github.oogasawa.utility.security.usn;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.HorizontalAlignment;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.VerticalAlignment;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFCellStyle;
import org.apache.poi.xssf.usermodel.XSSFColor;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Adds the rows of a report to the workbook that records how each notice was dealt with.
 *
 * <p>
 * The workbook is the record kept under document number {@code 【C-19】}. Each sheet holds one row
 * per notice. The first columns are the report produced by this program; the columns after them are
 * filled in by the people who decide and carry out the countermeasure.
 * </p>
 *
 * <h2>The source workbook is never written to</h2>
 *
 * <p>
 * The workbook carries a document number, a version and the name of the person who approved it, and
 * its rows hold decisions that people wrote by hand. This class reads the source workbook and
 * writes a separate file, so that whoever maintains the record compares the two and replaces the
 * original themselves, together with the version and the date that a change of a controlled
 * document requires.
 * </p>
 *
 * <h2>A new sheet is given the formatting of the sheet already there</h2>
 *
 * <p>
 * A sheet this class creates is given the column widths, the frozen heading row, the fonts, the
 * heading colours and the date formats that the {@code 2025} sheet carries, so that nobody has to
 * set them by hand after every run.
 * </p>
 */
public class PatchHistoryWorkbook {

    private static final Logger logger = LoggerFactory.getLogger(PatchHistoryWorkbook.class);

    /**
     * The severity of a row that a later run writes over.
     *
     * <p>
     * A run made while ubuntu.com was refusing writes this value. It says nothing about the notice;
     * it records a failure on this side. Every other severity is a fact about the notice, so a row
     * carrying one is never written over.
     * </p>
     */
    private static final String SEVERITY_LOOKUP_FAILED = "LookupFailed";

    /** Header of the columns that a report of Ubuntu Security Notices fills in. */
    private static final List<String> USN_REPORT_HEADERS = List.of(
            "", "title", "published_date", "summary", "severity", "reboot", "livepatch",
            "severe_cves");

    /** Width of each column of a report of Ubuntu Security Notices, as the 2025 sheet has them. */
    private static final double[] USN_REPORT_WIDTHS =
            {12.71, 25.71, 15.29, 45.57, 8.57, 7.14, 9.43, 40.00};

    /** Header of the columns that a report of Kernel Live Patch Security Notices fills in. */
    private static final List<String> LIVE_PATCH_REPORT_HEADERS = List.of(
            "id", "published_date", "summary", "severity", "flavours", "patch_version",
            "kernel_version", "cve_count", "severe_cves");

    /** Width of each column of a report of Kernel Live Patch Security Notices. */
    private static final double[] LIVE_PATCH_REPORT_WIDTHS =
            {12.71, 15.29, 45.57, 8.57, 12.00, 14.00, 15.00, 10.00, 40.00};

    /** Header of the columns that people fill in, taken from the sheet already there. */
    private static final List<String> MANUAL_HEADERS = List.of(
            "対策内容 (GW, dtn)",
            "対策日 (GW, dtn)",
            "対策内容 （計算ノード, VM, guacamole, 管理ノード)",
            "対策日 （計算ノード, VM, guacamole, 管理ノード)",
            "　対策内容 （スパコンHPなど）",
            "対策日 （スパコンHPなど）",
            "確認完了日",
            "確認者 (連名)",
            "備考");

    /** Width of each column that people fill in, as the 2025 sheet has them. */
    private static final double[] MANUAL_WIDTHS =
            {11.57, 14.43, 20.86, 15.14, 17.00, 25.43, 11.57, 7.43, 51.00};

    /** Which of the columns people fill in hold a date. */
    private static final Set<Integer> MANUAL_DATE_COLUMNS = Set.of(1, 3, 5, 6);

    /** Colour of the heading of the columns this program fills in. */
    private static final byte[] REPORT_HEADING_COLOUR = rgb(0x93, 0xC4, 0x7D);

    /** Colour of the heading of the columns people fill in. */
    private static final byte[] MANUAL_HEADING_COLOUR = rgb(0xFC, 0xE5, 0xCD);

    /** Date format used by the column that holds the publication date. */
    private static final String DATE_FORMAT = "yyyy-mm-dd";

    /** Font of every cell, as the 2025 sheet has it. */
    private static final String FONT_NAME = "Arial";

    private static byte[] rgb(int red, int green, int blue) {
        return new byte[] {(byte) red, (byte) green, (byte) blue};
    }

    /** The styles a sheet needs, built once per workbook. */
    private static class Styles {

        private final CellStyle reportHeading;
        private final CellStyle manualHeading;
        private final CellStyle text;
        private final CellStyle date;

        Styles(Workbook workbook) {
            Font font = workbook.createFont();
            font.setFontName(FONT_NAME);
            font.setFontHeightInPoints((short) 11);

            Font smallFont = workbook.createFont();
            smallFont.setFontName(FONT_NAME);
            smallFont.setFontHeightInPoints((short) 9);

            this.reportHeading = heading(workbook, font, REPORT_HEADING_COLOUR);
            this.manualHeading = heading(workbook, smallFont, MANUAL_HEADING_COLOUR);

            this.text = readable(workbook, font);

            this.date = readable(workbook, font);
            this.date.setAlignment(HorizontalAlignment.RIGHT);
            this.date.setDataFormat(workbook.createDataFormat().getFormat(DATE_FORMAT));
        }

        /**
         * Builds a style that shows the whole content of a cell.
         *
         * <p>
         * The text is aligned to the top and wrapped. A summary runs to several lines, and with the
         * bottom alignment Excel uses by default the first line of a tall cell sits far below the
         * short cells beside it, which makes a row hard to read across.
         * </p>
         *
         * @param workbook the workbook the style belongs to
         * @param font the font of the cell
         * @return the style
         */
        private static CellStyle readable(Workbook workbook, Font font) {
            CellStyle style = workbook.createCellStyle();
            style.setFont(font);
            style.setWrapText(true);
            style.setVerticalAlignment(VerticalAlignment.TOP);
            return style;
        }

        private static CellStyle heading(Workbook workbook, Font font, byte[] colour) {
            XSSFCellStyle style = (XSSFCellStyle) workbook.createCellStyle();
            style.setFont(font);
            style.setWrapText(true);
            style.setVerticalAlignment(VerticalAlignment.TOP);
            style.setFillForegroundColor(new XSSFColor(colour, null));
            style.setFillPattern(FillPatternType.SOLID_FOREGROUND);
            return style;
        }
    }

    /**
     * Writes a copy of the source workbook with a report of Ubuntu Security Notices added.
     *
     * @param sourceWorkbook the workbook to read, which is not modified
     * @param reportTsv the TSV produced by {@code ubuntu:report}
     * @param outputWorkbook the file to write
     * @param sheetName the sheet that receives the rows, for example {@code 2026}
     * @throws IOException if a file cannot be read or written
     */
    public void addReport(Path sourceWorkbook, Path reportTsv, Path outputWorkbook,
            String sheetName) throws IOException {
        addTable(sourceWorkbook, reportTsv, outputWorkbook, sheetName,
                USN_REPORT_HEADERS, USN_REPORT_WIDTHS, 4);
    }

    /**
     * Writes a copy of the source workbook with a report of Kernel Live Patch Security Notices
     * added.
     *
     * @param sourceWorkbook the workbook to read, which is not modified
     * @param reportTsv the TSV produced by {@code ubuntu:livepatch-report}
     * @param outputWorkbook the file to write
     * @param sheetName the sheet that receives the rows, for example {@code 2026-livepatch}
     * @throws IOException if a file cannot be read or written
     */
    public void addLivePatchReport(Path sourceWorkbook, Path reportTsv, Path outputWorkbook,
            String sheetName) throws IOException {
        addTable(sourceWorkbook, reportTsv, outputWorkbook, sheetName,
                LIVE_PATCH_REPORT_HEADERS, LIVE_PATCH_REPORT_WIDTHS, 3);
    }

    /**
     * Writes a copy of the source workbook with the rows of a report added to the named sheet.
     *
     * <p>
     * A notice already anywhere in the workbook is not written again, so running this twice adds
     * nothing the second time. The suffix of the identifier is ignored in that comparison, because
     * the report names a group of reissues after its earliest issue and an issue published earlier
     * than any seen before renames the group.
     * </p>
     *
     * <p>
     * A row already there is left as it is, with one exception: a row whose severity says the
     * priority could not be retrieved is written over, in the columns this program fills in.
     * </p>
     *
     * @param sourceWorkbook the workbook to read, which is not modified
     * @param reportTsv the report to add
     * @param outputWorkbook the file to write
     * @param sheetName the sheet that receives the rows
     * @param reportHeaders the header of the columns the report fills in
     * @param reportWidths the width of each of those columns
     * @param severityColumn the column holding the severity, counting from zero
     * @throws IOException if a file cannot be read or written
     */
    private void addTable(Path sourceWorkbook, Path reportTsv, Path outputWorkbook,
            String sheetName, List<String> reportHeaders, double[] reportWidths,
            int severityColumn) throws IOException {

        List<List<String>> reportRows = readReport(reportTsv, reportHeaders.size());
        logger.info("Read {} rows from {}", reportRows.size(), reportTsv);

        try (InputStream in = Files.newInputStream(sourceWorkbook);
                Workbook workbook = new XSSFWorkbook(in)) {

            Set<String> knownNoticeIds = collectNoticeIds(workbook);
            logger.info("The workbook already holds {} notices", knownNoticeIds.size());

            Styles styles = new Styles(workbook);

            Sheet sheet = workbook.getSheet(sheetName);
            if (sheet == null) {
                sheet = workbook.createSheet(sheetName);
                writeHeader(sheet, styles, reportHeaders);
                applySheetFormatting(sheet, reportWidths);
                logger.info("Created the sheet {}", sheetName);
            }

            Map<String, Row> rowsAwaitingARank = rowsWithoutARank(sheet, severityColumn);
            int rowIndex = lastFilledRowIndex(sheet) + 1;
            int added = 0;
            int repaired = 0;
            int skipped = 0;

            for (List<String> reportRow : reportRows) {
                String noticeId = USNJsonExporter.baseNoticeId(reportRow.get(0));
                Row awaiting = rowsAwaitingARank.get(noticeId);

                if (awaiting != null && !SEVERITY_LOOKUP_FAILED.equals(reportRow.get(
                        severityColumn))) {
                    writeRow(awaiting, reportRow, styles, reportHeaders.size(), false);
                    repaired++;
                    continue;
                }
                if (knownNoticeIds.contains(noticeId)) {
                    skipped++;
                    continue;
                }
                writeRow(sheet.createRow(rowIndex), reportRow, styles, reportHeaders.size(), true);
                knownNoticeIds.add(noticeId);
                rowIndex++;
                added++;
            }

            logger.info("Added {} rows to the sheet {}, gave a rank to {} rows that had none, "
                    + "and skipped {} notices already recorded", added, sheetName, repaired,
                    skipped);

            try (OutputStream out = Files.newOutputStream(outputWorkbook)) {
                workbook.write(out);
            }
            logger.info("Wrote {}", outputWorkbook);

            System.err.printf("Added %d rows to the sheet %s of %s (%d notices were already "
                    + "recorded).%n", added, sheetName, outputWorkbook, skipped);
            System.err.printf("The source workbook %s was not modified.%n", sourceWorkbook);
        }
    }

    /**
     * Reads the report, dropping its header line.
     *
     * @param reportTsv the report to read
     * @param columnCount how many columns the report has
     * @return one list of columns per notice
     * @throws IOException if the file cannot be read
     */
    static List<List<String>> readReport(Path reportTsv, int columnCount) throws IOException {
        List<List<String>> rows = new ArrayList<List<String>>();

        for (String line : Files.readAllLines(reportTsv, StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("id\t")) {
                continue;
            }
            String[] columns = line.split("\t", -1);
            List<String> row = new ArrayList<String>();
            for (int i = 0; i < columnCount; i++) {
                row.add(i < columns.length ? columns[i] : "");
            }
            rows.add(row);
        }
        return rows;
    }

    /**
     * Collects the notice identifiers already present in the first column of every sheet.
     *
     * @param workbook the workbook to scan
     * @return the identifiers found
     */
    static Set<String> collectNoticeIds(Workbook workbook) {
        // The suffix is dropped, so that a notice already in the record is recognised however its
        // representative issue changed. Canonical issues the same fix again for each kernel
        // flavour, giving each issue the same number with a different suffix, and the report names
        // the group after its earliest issue. An issue published earlier than any seen so far
        // therefore renames the group, and matching the whole identifier would put the same notice
        // in the record a second time under the new name.

        Set<String> ids = new HashSet<String>();

        for (Sheet sheet : workbook) {
            for (Row row : sheet) {
                Cell cell = row.getCell(0);
                if (cell == null) {
                    continue;
                }
                String value = readAsText(cell);
                if (value.startsWith("USN-") || value.startsWith("LSN-")) {
                    ids.add(USNJsonExporter.baseNoticeId(value));
                }
            }
        }
        return ids;
    }

    /**
     * Returns the index of the last row that holds a notice identifier.
     *
     * @param sheet the sheet to scan
     * @return the index, or {@code 0} when only the header is present
     */
    static int lastFilledRowIndex(Sheet sheet) {
        int last = 0;
        for (Row row : sheet) {
            Cell cell = row.getCell(0);
            if (cell != null && !readAsText(cell).isBlank()) {
                last = row.getRowNum();
            }
        }
        return last;
    }

    /**
     * Freezes the heading row and sets the width of every column.
     *
     * @param sheet the sheet to format
     * @param reportWidths the width of each column the report fills in
     */
    private static void applySheetFormatting(Sheet sheet, double[] reportWidths) {
        sheet.createFreezePane(0, 1);

        int column = 0;
        for (double width : reportWidths) {
            sheet.setColumnWidth(column++, (int) (width * 256));
        }
        for (double width : MANUAL_WIDTHS) {
            sheet.setColumnWidth(column++, (int) (width * 256));
        }
    }

    /**
     * Writes the heading of a newly created sheet.
     *
     * @param sheet the sheet to write to
     * @param styles the styles of the workbook
     * @param reportHeaders the header of the columns the report fills in
     */
    private static void writeHeader(Sheet sheet, Styles styles, List<String> reportHeaders) {
        Row header = sheet.createRow(0);
        int column = 0;
        for (String text : reportHeaders) {
            Cell cell = header.createCell(column++);
            cell.setCellValue(text);
            cell.setCellStyle(styles.reportHeading);
        }
        for (String text : MANUAL_HEADERS) {
            Cell cell = header.createCell(column++);
            cell.setCellValue(text);
            cell.setCellStyle(styles.manualHeading);
        }
    }

    /**
     * Writes one notice, leaving the columns for people empty but formatted.
     *
     * @param row the row to write to
     * @param reportRow the columns of the report
     * @param styles the styles of the workbook
     * @param reportColumnCount how many columns the report fills in
     * @param newRow true when the row is new, so that the columns for people are given their
     *        formatting. A row being written over keeps whatever people wrote in them.
     */
    private static void writeRow(Row row, List<String> reportRow, Styles styles,
            int reportColumnCount, boolean newRow) {

        for (int column = 0; column < reportRow.size(); column++) {
            // A cell already holding a value is removed rather than written over. A writer other
            // than this one may have stored the text of the cell in place, as an inline string,
            // and setting a new value on such a cell replaces only one of the two places the text
            // sits in. The cell then reads as the new value to this program and as the old one to
            // a spreadsheet program. Building the cell afresh leaves one value in it.
            Cell existing = row.getCell(column);
            if (existing != null) {
                row.removeCell(existing);
            }
            Cell cell = row.createCell(column);
            cell.setCellValue(reportRow.get(column));
            cell.setCellStyle(styles.text);
        }

        if (!newRow) {
            return;
        }
        for (int i = 0; i < MANUAL_HEADERS.size(); i++) {
            Cell cell = row.createCell(reportColumnCount + i);
            cell.setCellStyle(MANUAL_DATE_COLUMNS.contains(i) ? styles.date : styles.text);
        }
    }

    /**
     * Finds the rows whose severity says the priority could not be retrieved.
     *
     * <p>
     * A row written while ubuntu.com was refusing carries {@link #SEVERITY_LOOKUP_FAILED}. It is
     * the one kind of row a later run should write over, because the value in it is not a fact
     * about the notice but a record of a failure on this side. Every other row is left alone.
     * </p>
     *
     * @param sheet the sheet to scan
     * @param severityColumn the column holding the severity, counting from zero
     * @return the rows, by notice identifier
     */
    private static Map<String, Row> rowsWithoutARank(Sheet sheet, int severityColumn) {
        Map<String, Row> rows = new HashMap<String, Row>();

        for (Row row : sheet) {
            Cell id = row.getCell(0);
            Cell severity = row.getCell(severityColumn);
            if (id == null || severity == null) {
                continue;
            }
            if (SEVERITY_LOOKUP_FAILED.equals(readAsText(severity))) {
                rows.put(USNJsonExporter.baseNoticeId(readAsText(id)), row);
            }
        }
        return rows;
    }

    /**
     * Reads a cell as text whatever its type.
     *
     * @param cell the cell to read
     * @return the text of the cell, trimmed
     */
    private static String readAsText(Cell cell) {
        switch (cell.getCellType()) {
            case STRING:
                return cell.getStringCellValue().trim();
            case NUMERIC:
                return String.valueOf(cell.getNumericCellValue()).trim();
            case BOOLEAN:
                return String.valueOf(cell.getBooleanCellValue());
            default:
                return "";
        }
    }
}
