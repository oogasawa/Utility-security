#!/bin/bash
#
# Adds the Ubuntu Security Notices and the Kernel Live Patch Security Notices published
# recently to the patch history record, and leaves the record in place of the old one.
#
# A run goes through these states:
#
#   1. Alone           the lock is held, so no other run is in progress.
#   2. Reported        both reports have been written as tab separated files.
#   3. Candidate       a copy of the record carrying the new rows exists beside it.
#   4. Recorded        the old record is in the backup directory and the candidate is the record.
#
# A run that fails leaves the record untouched, whichever state it reached.
#
set -u -o pipefail

export LANG=ja_JP.UTF-8
export LC_ALL=ja_JP.UTF-8

# cron runs with a short PATH that does not carry the java installed by sdkman, so the program
# is named outright rather than looked up.
JAVA="${JAVA_BIN:-$HOME/.sdkman/candidates/java/current/bin/java}"
RECORD="${PATCH_HISTORY_RECORD:-$HOME/Downloads/【C-19】セキュリティパッチ対策履歴.xlsx}"
JAR="${UTILITY_SECURITY_JAR:-$HOME/works/Utility-security.jar}"
RELEASE="${UBUNTU_RELEASE:-noble}"
WORK_DIR="$HOME/logs-security/patch-history"
BACKUP_DIR="$WORK_DIR/backup"
LOG_FILE="$WORK_DIR/update-patch-history.log"
LOCK_FILE="$WORK_DIR/update-patch-history.lock"
BACKUPS_KEPT=12

mkdir -p "$WORK_DIR" "$BACKUP_DIR"

log() {
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE"
}

die() {
    log "FAILED: $*"
    # A workbook left behind by a run that failed must not be mistaken for a good record. The
    # two reports stay, because they say what the run had read when it stopped.
    rm -f "${INTERMEDIATE:-}" "${CANDIDATE:-}"
    exit 1
}

# State 1: alone. A run takes about an hour, so a run started while another is still going
# would read a record that the other one is about to replace.
exec 9> "$LOCK_FILE"
flock -n 9 || { log "another run is in progress; nothing done"; exit 0; }

[ -x "$JAVA" ] || die "java is not at $JAVA"
[ -r "$JAR" ] || die "the program is not at $JAR"
[ -r "$RECORD" ] || die "the record is not at $RECORD"

# True when the record already holds a sheet of this name. A workbook is a zip archive, and the
# names of its sheets sit in one file inside it.
holds_sheet() {
    unzip -p "$1" xl/workbook.xml 2>/dev/null | LC_ALL=C fgrep -q "name=\"$2\""
}

# The window ends today and reaches back a month, so that a notice missed by a run that failed
# is picked up by the next one. A notice already in the record is not written again, so the
# overlap costs nothing. The window never crosses into last year, because a notice published
# last year belongs in last year's sheet.
#
# The first run of a year has nothing to reach back to: the record holds no sheet for the year,
# so a month-wide window would leave every notice published earlier in the year out of the
# record for good. That run takes the whole year so far, or the period named by
# PATCH_HISTORY_START when the record is meant to start later than the first of January.
YEAR=$(date '+%Y')
END=$(date '+%Y-%m-%d')
if holds_sheet "$RECORD" "$YEAR"; then
    START=$(date -d '30 days ago' '+%Y-%m-%d')
    if [[ "$START" < "$YEAR-01-01" ]]; then
        START="$YEAR-01-01"
    fi
else
    START="${PATCH_HISTORY_START:-$YEAR-01-01}"
fi

STAMP=$(date '+%Y%m%d%H%M')
USN_REPORT="$WORK_DIR/usn-$STAMP.tsv"
LSN_REPORT="$WORK_DIR/lsn-$STAMP.tsv"
CANDIDATE="$WORK_DIR/record-$STAMP.xlsx"
INTERMEDIATE="$WORK_DIR/record-$STAMP.usn.xlsx"

# Runs the program, sending what it says about its progress to the log. The program writes
# its log to the error stream, so a report on the standard stream is a report and nothing else.
run() {
    nice -n 19 "$JAVA" -Dfile.encoding=UTF-8 -jar "$JAR" "$@" >> "$LOG_FILE" 2>&1
}

# Runs the program and keeps the report it writes on the standard stream.
report_to() {
    local destination="$1"
    shift
    nice -n 19 "$JAVA" -Dfile.encoding=UTF-8 -jar "$JAR" "$@" > "$destination" 2>> "$LOG_FILE"
}

# The number of lines a report holds, not counting its heading. A file without the heading is
# not a report at all: the command turns bad arguments away with a message and stops, leaving
# an empty file behind, and this tells that apart from a period holding no notice.
notice_count() {
    local file="$1"
    local heading=""
    [ -s "$file" ] && IFS= read -r heading < "$file"
    case "$heading" in
        id$'\t'*) echo $(( $(wc -l < "$file") - 1 )) ;;
        *) echo -1 ;;
    esac
}

log "=== $START to $END, release $RELEASE, sheets $YEAR and $YEAR-livepatch"

# State 2: reported.
report_to "$USN_REPORT" ubuntu:report -S "$START" -E "$END" -r "$RELEASE" --format tsv \
    || die "ubuntu:report ended with an error"
USN_COUNT=$(notice_count "$USN_REPORT")
[ "$USN_COUNT" -ge 0 ] || die "ubuntu:report wrote no report; see the messages above"
log "ubuntu:report wrote $USN_COUNT Ubuntu Security Notices"
# Canonical publishes several notices a week, so a month holding none means the run read
# nothing rather than that nothing was published.
[ "$USN_COUNT" -gt 0 ] || die "no Ubuntu Security Notice was retrieved for $START to $END"

report_to "$LSN_REPORT" ubuntu:livepatch-report -S "$START" -E "$END" -r "$RELEASE" \
    || die "ubuntu:livepatch-report ended with an error"
LSN_COUNT=$(notice_count "$LSN_REPORT")
# Canonical publishes a Kernel Live Patch Security Notice every few weeks, so a month holding
# none is ordinary. A report without its heading is not.
[ "$LSN_COUNT" -ge 0 ] || die "ubuntu:livepatch-report wrote no report; see the messages above"
log "ubuntu:livepatch-report wrote $LSN_COUNT Kernel Live Patch Security Notices"

# State 3: candidate. Neither command writes the record; each reads one workbook and writes
# another, so the record is still the old one until the move below.
run ubuntu:append-xlsx -k usn -i "$USN_REPORT" -x "$RECORD" -o "$INTERMEDIATE" -s "$YEAR" \
    || die "adding the Ubuntu Security Notices to the record ended with an error"
run ubuntu:append-xlsx -k livepatch -i "$LSN_REPORT" -x "$INTERMEDIATE" -o "$CANDIDATE" \
    -s "$YEAR-livepatch" \
    || die "adding the Kernel Live Patch Security Notices to the record ended with an error"

[ -s "$CANDIDATE" ] || die "no candidate record was written"

# A workbook is a zip archive holding one file per sheet. Reading the archive tells a workbook
# cut short by a full disk or a killed process from a whole one, and counting the sheets tells
# that none was dropped. The size in bytes says nothing: two writers compress the same rows to
# different lengths, so a candidate carrying more rows can be the smaller file.
unzip -qq -t "$CANDIDATE" > /dev/null 2>&1 || die "the candidate is not a readable workbook"
sheet_count() {
    unzip -Z1 "$1" 2>/dev/null | LC_ALL=C fgrep -c 'xl/worksheets/sheet'
}
CANDIDATE_SHEETS=$(sheet_count "$CANDIDATE")
RECORD_SHEETS=$(sheet_count "$RECORD")
[ "$CANDIDATE_SHEETS" -ge "$RECORD_SHEETS" ] \
    || die "the candidate holds $CANDIDATE_SHEETS sheets against the record's $RECORD_SHEETS"

# State 4: recorded.
BACKUP="$BACKUP_DIR/$(basename "$RECORD" .xlsx)-$STAMP.xlsx"
cp -p "$RECORD" "$BACKUP" || die "the record could not be copied to $BACKUP"
mv "$CANDIDATE" "$RECORD" || die "the candidate could not be put in place of the record"
log "the record now carries the notices; the old one is at $BACKUP"

rm -f "$INTERMEDIATE"

# Only the newest of each kind are kept, so that the directory does not grow without bound.
prune() {
    ls -1t $1 2>/dev/null | tail -n +$((BACKUPS_KEPT + 1)) | while read -r old; do
        rm -f "$old"
        log "removed $old"
    done
}
prune "$BACKUP_DIR/*.xlsx"
prune "$WORK_DIR/usn-*.tsv"
prune "$WORK_DIR/lsn-*.tsv"

log "=== done"
