package com.github.oogasawa.utility.security.usn;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.CellType;
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
    private static final String SEVERITY_LOOKUP_FAILED = USNJsonExporter.SEVERITY_LOOKUP_FAILED;

    /**
     * The severity of a row written before its CVEs were looked up.
     *
     * <p>
     * Like {@link #SEVERITY_LOOKUP_FAILED} it says nothing about the notice, so a later run writes
     * over the row.
     * </p>
     */
    private static final String SEVERITY_PENDING = USNJsonExporter.SEVERITY_PENDING;

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

    /** Header of the columns that a report of CVEs other than Ubuntu's fills in. */
    private static final List<String> CVE_REPORT_HEADERS = List.of(
            "id", "category", "cve", "published_date", "target", "severity", "cvss", "fixed",
            "summary");

    /** Width of each column of a report of CVEs other than Ubuntu's. */
    private static final double[] CVE_REPORT_WIDTHS =
            {18.00, 11.00, 22.00, 15.29, 38.00, 11.00, 7.00, 38.00, 60.00};

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

                if (awaiting != null && isSettled(reportRow.get(severityColumn))) {
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
     * Writes a copy of the source workbook with a report of CVEs other than Ubuntu's added.
     *
     * <p>
     * A row is identified by its id and its category: one advisory is one row. Of a row already
     * in the sheet only the target is rewritten, when the projects the advisory affects have
     * changed; every other cell, and everything people wrote beside it, stays.
     * </p>
     *
     * @param sourceWorkbook the workbook to read, which is not modified
     * @param reportTsv the report to add, whose columns are those of {@link #CVE_REPORT_HEADERS}
     * @param outputWorkbook the file to write
     * @param sheetName the sheet that receives the rows
     * @throws IOException if a file cannot be read or written
     */
    public void addCveReport(Path sourceWorkbook, Path reportTsv, Path outputWorkbook,
            String sheetName) throws IOException {

        List<List<String>> reportRows = readReport(reportTsv, CVE_REPORT_HEADERS.size());

        try (InputStream in = Files.newInputStream(sourceWorkbook);
                Workbook workbook = new XSSFWorkbook(in)) {

            Styles styles = new Styles(workbook);
            Sheet sheet = workbook.getSheet(sheetName);
            if (sheet == null) {
                sheet = workbook.createSheet(sheetName);
                writeHeader(sheet, styles, CVE_REPORT_HEADERS);
                applySheetFormatting(sheet, CVE_REPORT_WIDTHS);
                logger.info("Created the sheet {}", sheetName);
            }

            Map<String, Row> known = new HashMap<String, Row>();
            for (Row row : sheet) {
                if (row.getRowNum() == 0) {
                    continue;
                }
                known.put(cveRowKey(cellText(row, 0), cellText(row, 1)), row);
            }

            int rowIndex = lastFilledRowIndex(sheet) + 1;
            int added = 0;
            int retargeted = 0;
            for (List<String> reportRow : reportRows) {
                String key = cveRowKey(reportRow.get(0), reportRow.get(1));
                Row recorded = known.get(key);
                if (recorded != null) {
                    // The projects an advisory affects change as projects update their
                    // libraries; the target is the program's own column, so it follows.
                    if (!cellText(recorded, 4).equals(reportRow.get(4))) {
                        replaceText(recorded, 4, reportRow.get(4));
                        retargeted++;
                    }
                    continue;
                }
                known.put(key, null);
                writeRow(sheet.createRow(rowIndex++), reportRow, styles,
                        CVE_REPORT_HEADERS.size(), true);
                added++;
            }
            sortByPublicationDate(sheet);

            try (OutputStream out = Files.newOutputStream(outputWorkbook)) {
                workbook.write(out);
            }
            System.err.printf("Added %d rows to the sheet %s of %s (%d were already recorded, "
                    + "%d of them with a new target).%n",
                    added, sheetName, outputWorkbook, reportRows.size() - added, retargeted);
            System.err.printf("The source workbook %s was not modified.%n", sourceWorkbook);
        }
    }

    /**
     * Orders the rows of a sheet of CVEs other than Ubuntu's by publication date, oldest first.
     *
     * <p>
     * The sheet reads from the top down in the order the CVEs were published, as the sheets of
     * Ubuntu notices do. The reports arrive in whatever order their sources answer, and the rows
     * of a later run are added below the earlier ones, so the sheet is put in order after every
     * addition. A row moves whole, with every cell people wrote beside it. Rows published on the
     * same day are ordered by category, id and target, so that two runs give the same order.
     * </p>
     *
     * @param sheet the sheet to order, whose first row is the header
     */
    static void sortByPublicationDate(Sheet sheet) {

        record CellCopy(int column, CellStyle style, CellType type, Object value) {}
        record RowCopy(String key, short height, List<CellCopy> cells) {}

        List<RowCopy> rows = new ArrayList<RowCopy>();
        for (int i = 1; i <= sheet.getLastRowNum(); i++) {
            Row row = sheet.getRow(i);
            if (row == null) {
                continue;
            }
            List<CellCopy> cells = new ArrayList<CellCopy>();
            for (Cell cell : row) {
                cells.add(switch (cell.getCellType()) {
                    case NUMERIC -> new CellCopy(cell.getColumnIndex(), cell.getCellStyle(),
                            CellType.NUMERIC, cell.getNumericCellValue());
                    case BOOLEAN -> new CellCopy(cell.getColumnIndex(), cell.getCellStyle(),
                            CellType.BOOLEAN, cell.getBooleanCellValue());
                    case FORMULA -> new CellCopy(cell.getColumnIndex(), cell.getCellStyle(),
                            CellType.FORMULA, cell.getCellFormula());
                    case STRING -> new CellCopy(cell.getColumnIndex(), cell.getCellStyle(),
                            CellType.STRING, cell.getStringCellValue());
                    default -> new CellCopy(cell.getColumnIndex(), cell.getCellStyle(),
                            CellType.BLANK, null);
                });
            }
            String key = String.join("\t", cellText(row, 3), cellText(row, 1), cellText(row, 0),
                    cellText(row, 4));
            rows.add(new RowCopy(key, row.getHeight(), cells));
            sheet.removeRow(row);
        }

        rows.sort(java.util.Comparator.comparing(RowCopy::key));

        int rowIndex = 1;
        for (RowCopy copy : rows) {
            Row row = sheet.createRow(rowIndex++);
            row.setHeight(copy.height());
            for (CellCopy cellCopy : copy.cells()) {
                Cell cell = row.createCell(cellCopy.column());
                cell.setCellStyle(cellCopy.style());
                switch (cellCopy.type()) {
                    case NUMERIC -> cell.setCellValue((Double) cellCopy.value());
                    case BOOLEAN -> cell.setCellValue((Boolean) cellCopy.value());
                    case FORMULA -> cell.setCellFormula((String) cellCopy.value());
                    case STRING -> cell.setCellValue((String) cellCopy.value());
                    default -> cell.setBlank();
                }
            }
        }
    }

    private static String cveRowKey(String id, String category) {
        return id + "\t" + category;
    }

    private static String cellText(Row row, int column) {
        Cell cell = row.getCell(column);
        return cell == null ? "" : readAsText(cell);
    }

    /**
     * Writes the severity and the severe CVEs of one Ubuntu Security Notice into the record, in
     * place.
     *
     * @param record the workbook to change
     * @param sheetName the sheet holding the notice
     * @param noticeId the identifier of the notice
     * @param severity the severity to write
     * @param severeCves the CVEs whose priority is High or Critical
     * @return true when a row was written
     * @throws IOException if the workbook cannot be read or written
     */
    public boolean updateUsnRating(Path record, String sheetName, String noticeId,
            String severity, List<String> severeCves) throws IOException {
        return updateRating(record, sheetName, noticeId, 4, 7, severity, severeCves);
    }

    /**
     * Writes the severity and the severe CVEs of one Kernel Live Patch Security Notice into the
     * record, in place.
     *
     * @param record the workbook to change
     * @param sheetName the sheet holding the notice
     * @param noticeId the identifier of the notice
     * @param severity the severity to write
     * @param severeCves the CVEs whose priority is High or Critical
     * @return true when a row was written
     * @throws IOException if the workbook cannot be read or written
     */
    public boolean updateLivePatchRating(Path record, String sheetName, String noticeId,
            String severity, List<String> severeCves) throws IOException {
        return updateRating(record, sheetName, noticeId, 3, 8, severity, severeCves);
    }

    /**
     * Writes the severity and the severe CVEs of one notice into the row that is waiting for them.
     *
     * <p>
     * Only a row whose severity is a placeholder is written, and only its severity and severe CVEs
     * cells. Everything else in the row, including what people wrote, is left as it is. The new
     * workbook is written beside the record and moved over it in one step, after it has been read
     * back, so that a run killed in the middle leaves the record whole.
     * </p>
     *
     * @param record the workbook to change
     * @param sheetName the sheet holding the notice
     * @param noticeId the identifier of the notice
     * @param severityColumn the column holding the severity, counting from zero
     * @param severeCvesColumn the column holding the severe CVEs, counting from zero
     * @param severity the severity to write
     * @param severeCves the CVEs whose priority is High or Critical
     * @return true when a row was written
     * @throws IOException if the workbook cannot be read or written
     */
    private boolean updateRating(Path record, String sheetName, String noticeId,
            int severityColumn, int severeCvesColumn, String severity, List<String> severeCves)
            throws IOException {

        Path temporary = record.resolveSibling(record.getFileName() + ".updating");
        int sheetsBefore;

        try (InputStream in = Files.newInputStream(record);
                Workbook workbook = new XSSFWorkbook(in)) {

            sheetsBefore = workbook.getNumberOfSheets();
            Sheet sheet = workbook.getSheet(sheetName);
            if (sheet == null) {
                logger.warn("The record has no sheet {} for {}", sheetName, noticeId);
                return false;
            }
            Row row = rowsWithoutARank(sheet, severityColumn)
                    .get(USNJsonExporter.baseNoticeId(noticeId));
            if (row == null) {
                logger.info("{} has no row waiting for a severity in the sheet {}", noticeId,
                        sheetName);
                return false;
            }

            replaceText(row, severityColumn, severity);
            replaceText(row, severeCvesColumn, String.join(" ", severeCves));

            try (OutputStream out = Files.newOutputStream(temporary)) {
                workbook.write(out);
            }
        }

        try (InputStream in = Files.newInputStream(temporary);
                Workbook written = new XSSFWorkbook(in)) {
            if (written.getNumberOfSheets() < sheetsBefore) {
                Files.deleteIfExists(temporary);
                throw new IOException("The workbook written for " + noticeId + " holds "
                        + written.getNumberOfSheets() + " sheets against " + sheetsBefore);
            }
        }
        Files.setPosixFilePermissions(temporary, Files.getPosixFilePermissions(record));
        Files.move(temporary, record, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        logger.info("Wrote severity {} for {} in the sheet {}", severity, noticeId, sheetName);
        return true;
    }

    /**
     * Replaces the text of one cell, keeping its style.
     *
     * @param row the row holding the cell
     * @param column the column of the cell, counting from zero
     * @param text the new text
     */
    private static void replaceText(Row row, int column, String text) {
        Cell existing = row.getCell(column);
        CellStyle style = existing != null ? existing.getCellStyle()
                : row.getCell(0).getCellStyle();
        if (existing != null) {
            // Built afresh for the reason given in writeRow.
            row.removeCell(existing);
        }
        Cell cell = row.createCell(column);
        cell.setCellValue(text);
        cell.setCellStyle(style);
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
            if (!isSettled(readAsText(severity))) {
                rows.put(USNJsonExporter.baseNoticeId(readAsText(id)), row);
            }
        }
        return rows;
    }

    /**
     * Tells whether a severity is a fact about the notice.
     *
     * <p>
     * {@link #SEVERITY_PENDING} says the CVEs have not been looked up yet,
     * {@link #SEVERITY_LOOKUP_FAILED} says a lookup failed, and a rank followed by {@code +} says
     * only that the severity is at least that rank. None of them is the severity of the notice, so
     * a row carrying one waits for a later run to write over it, and a report row carrying one
     * never writes over anything.
     * </p>
     *
     * @param severity the text of a severity cell
     * @return false when the severity is a placeholder
     */
    private static boolean isSettled(String severity) {
        return !SEVERITY_PENDING.equals(severity) && !SEVERITY_LOOKUP_FAILED.equals(severity)
                && !severity.endsWith(USNJsonExporter.SEVERITY_AT_LEAST_SUFFIX);
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
