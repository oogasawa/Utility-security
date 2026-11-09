#!/bin/bash
#
# Adds the Ubuntu Security Notices and the Kernel Live Patch Security Notices published
# recently to the patch history record, and leaves the record in place of the old one.
#
# The record is written twice, because looking up the CVEs of the notices is the slow part and
# depends on ubuntu.com answering. Nothing a person reads in the record depends on it except
# the severity and the severe CVEs.
#
# A run goes through these states:
#
#   1. Alone           the lock is held, so no other run is in progress.
#   2. Noticed         the notices are in the record, with the severity marked Pending.
#   3. Other CVEs      the sheet usn以外のcve holds the CVEs of FortiOS and of the Java projects.
#   4. Rated           the severity and the severe CVEs of the Ubuntu notices are in the record.
#
# State 2 is reached by writing a candidate copy of the record beside it, checking the candidate,
# copying the old record to the backup directory and moving the candidate into place. State 4 is
# reached one notice at a time: the program writes each notice's highest rank so far into the
# record whenever it changes, through a copy that replaces the record in one step, with a + while
# CVEs of the notice are still waiting. A run that stops in the middle leaves the notices with a
# + or Pending, and the next run rates them again. A notice of which no CVE could be looked up is
# marked LookupFailed and is rated again the same way.
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

# State 1: alone. A run can take hours, so a run started while another is still going would
# read a record that the other one is about to replace.
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
CANDIDATE=""
INTERMEDIATE=""

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

# A workbook is a zip archive holding one file per sheet. Reading the archive tells a workbook
# cut short by a full disk or a killed process from a whole one, and counting the sheets tells
# that none was dropped. The size in bytes says nothing: two writers compress the same rows to
# different lengths, so a candidate carrying more rows can be the smaller file.
sheet_count() {
    unzip -Z1 "$1" 2>/dev/null | LC_ALL=C fgrep -c 'xl/worksheets/sheet'
}

# Writes the two reports of a stage and counts what they hold. The extra arguments are given to
# both commands: --no-cve in the first stage, nothing in the second.
write_reports() {
    local usn_report="$1"
    local lsn_report="$2"
    shift 2

    report_to "$usn_report" ubuntu:report -S "$START" -E "$END" -r "$RELEASE" --format tsv "$@" \
        || die "ubuntu:report ended with an error"
    USN_COUNT=$(notice_count "$usn_report")
    [ "$USN_COUNT" -ge 0 ] || die "ubuntu:report wrote no report; see the messages above"
    log "ubuntu:report wrote $USN_COUNT Ubuntu Security Notices"
    # Canonical publishes several notices a week, so a month holding none means the run read
    # nothing rather than that nothing was published.
    [ "$USN_COUNT" -gt 0 ] || die "no Ubuntu Security Notice was retrieved for $START to $END"

    report_to "$lsn_report" ubuntu:livepatch-report -S "$START" -E "$END" -r "$RELEASE" "$@" \
        || die "ubuntu:livepatch-report ended with an error"
    LSN_COUNT=$(notice_count "$lsn_report")
    # Canonical publishes a Kernel Live Patch Security Notice every few weeks, so a month holding
    # none is ordinary. A report without its heading is not.
    [ "$LSN_COUNT" -ge 0 ] || die "ubuntu:livepatch-report wrote no report; see the messages above"
    log "ubuntu:livepatch-report wrote $LSN_COUNT Kernel Live Patch Security Notices"
}

# Puts the two reports in the record. Neither command writes the record; each reads one workbook
# and writes another, so the record is still the old one until the move at the end.
record_reports() {
    local usn_report="$1"
    local lsn_report="$2"
    local commit_stamp
    commit_stamp=$(date '+%Y%m%d%H%M%S')
    CANDIDATE="$WORK_DIR/record-$commit_stamp.xlsx"
    INTERMEDIATE="$WORK_DIR/record-$commit_stamp.usn.xlsx"

    run ubuntu:append-xlsx -k usn -i "$usn_report" -x "$RECORD" -o "$INTERMEDIATE" -s "$YEAR" \
        || die "adding the Ubuntu Security Notices to the record ended with an error"
    run ubuntu:append-xlsx -k livepatch -i "$lsn_report" -x "$INTERMEDIATE" -o "$CANDIDATE" \
        -s "$YEAR-livepatch" \
        || die "adding the Kernel Live Patch Security Notices to the record ended with an error"

    [ -s "$CANDIDATE" ] || die "no candidate record was written"

    unzip -qq -t "$CANDIDATE" > /dev/null 2>&1 || die "the candidate is not a readable workbook"
    local candidate_sheets record_sheets
    candidate_sheets=$(sheet_count "$CANDIDATE")
    record_sheets=$(sheet_count "$RECORD")
    [ "$candidate_sheets" -ge "$record_sheets" ] \
        || die "the candidate holds $candidate_sheets sheets against the record's $record_sheets"

    local backup
    backup="$BACKUP_DIR/$(basename "$RECORD" .xlsx)-$commit_stamp.xlsx"
    cp -p "$RECORD" "$backup" || die "the record could not be copied to $backup"
    mv "$CANDIDATE" "$RECORD" || die "the candidate could not be put in place of the record"
    log "the record now carries the notices; the old one is at $backup"

    rm -f "$INTERMEDIATE"
    CANDIDATE=""
    INTERMEDIATE=""
}

log "=== $START to $END, release $RELEASE, sheets $YEAR and $YEAR-livepatch"

# State 2: noticed. The reports are made without looking up a CVE, so this stage takes about a
# minute whether or not ubuntu.com is answering its CVE pages.
PENDING_USN="$WORK_DIR/usn-$STAMP.pending.tsv"
PENDING_LSN="$WORK_DIR/lsn-$STAMP.pending.tsv"
write_reports "$PENDING_USN" "$PENDING_LSN" --no-cve
record_reports "$PENDING_USN" "$PENDING_LSN"
rm -f "$PENDING_USN" "$PENDING_LSN"
log "state noticed"

# State 3: other CVEs. The sheet "usn以外のcve" lists the CVEs of FortiOS and of the Maven
# It comes before the rating of the Ubuntu notices, which can take days when ubuntu.com is
# slow, so that the sheet is brought up to date every week whatever the rating does.
# dependencies of the Java projects, which no Ubuntu notice covers. This stage is not part of
# the record's Ubuntu states: whatever goes wrong in it is logged and the record is left as the
# earlier states made it. The sheet is written to a candidate beside the record and moved into
# place the way state 2 does it, and a row already in the sheet is never written again, so what
# people wrote beside a row stays.
OTHER_SHEET="usn以外のcve"
FORTIOS_VERSIONS="${FORTIOS_VERSIONS:-7.4.6,7.4.11}"
JAVA_WORKS_DIR="${JAVA_CVE_WORKS_DIR:-$HOME/works}"

other_cves() {
    # cron's PATH carries neither mvn nor java; the Java stage runs mvn dependency:list.
    export JAVA_HOME="${JAVA_HOME:-$HOME/.sdkman/candidates/java/current}"
    export PATH="$JAVA_HOME/bin:$HOME/.sdkman/candidates/maven/current/bin:$PATH"

    local stamp fortinet_report java_report step1 step2 backup
    stamp=$(date '+%Y%m%d%H%M%S')
    fortinet_report="$WORK_DIR/fortinet-$stamp.tsv"
    java_report="$WORK_DIR/java-cve-$stamp.tsv"
    step1="$WORK_DIR/record-$stamp.other1.xlsx"
    step2="$WORK_DIR/record-$stamp.other2.xlsx"

    report_to "$fortinet_report" fortinet:report -V "$FORTIOS_VERSIONS" -S "$YEAR-01-01" \
        || { log "fortinet:report ended with an error; the sheet $OTHER_SHEET is not updated"; return 1; }
    [ "$(notice_count "$fortinet_report")" -ge 0 ] \
        || { log "fortinet:report wrote no report"; return 1; }

    report_to "$java_report" java:cve-report -w "$JAVA_WORKS_DIR" --format sheet \
        || { log "java:cve-report ended with an error; the sheet $OTHER_SHEET is not updated"; return 1; }
    [ "$(notice_count "$java_report")" -ge 0 ] \
        || { log "java:cve-report wrote no report"; return 1; }

    run cve:append-xlsx -i "$fortinet_report" -x "$RECORD" -o "$step1" -s "$OTHER_SHEET" \
        && run cve:append-xlsx -i "$java_report" -x "$step1" -o "$step2" -s "$OTHER_SHEET" \
        || { log "adding the CVEs to the record ended with an error"; rm -f "$step1" "$step2"; return 1; }

    if [ ! -s "$step2" ] || ! unzip -qq -t "$step2" > /dev/null 2>&1 \
            || [ "$(sheet_count "$step2")" -lt "$(sheet_count "$RECORD")" ]; then
        log "the candidate with the other CVEs is not a whole workbook; the record is left as it is"
        rm -f "$step1" "$step2"
        return 1
    fi

    backup="$BACKUP_DIR/$(basename "$RECORD" .xlsx)-$stamp-other-cves.xlsx"
    cp -p "$RECORD" "$backup" && mv "$step2" "$RECORD" \
        || { log "the candidate could not be put in place of the record"; rm -f "$step1" "$step2"; return 1; }
    rm -f "$step1"
    log "state other CVEs; the old record is at $backup"
}

other_cves || log "state other CVEs failed; see the messages above"

# State 4: rated. The CVEs are looked up, which is the part that can take hours. The notices take
# turns, one CVE request each per turn, and the highest rank obtained so far for a notice is
# written into the record whenever it changes, marked with + while CVEs of the notice are still
# waiting. A run that has not ended by the Monday meeting therefore leaves every notice with a
# rank from at least one of its CVEs. The record is copied once before the first of those writes.
RATING_BACKUP="$BACKUP_DIR/$(basename "$RECORD" .xlsx)-$(date '+%Y%m%d%H%M%S').xlsx"
cp -p "$RECORD" "$RATING_BACKUP" || die "the record could not be copied to $RATING_BACKUP"
log "the record before rating is at $RATING_BACKUP"

# The first pass makes no request: it writes what the stored CVE priorities already settle, so
# that the record shows it at once. A notice with a CVE not stored is marked LookupFailed unless
# a stored CVE is Critical, which settles it.
run ubuntu:rate-xlsx --stored-only -k livepatch -x "$RECORD" -s "$YEAR-livepatch" -S "$START" \
    -E "$END" -r "$RELEASE" \
    || die "rating the Kernel Live Patch Security Notices from the stored priorities ended with an error"
run ubuntu:rate-xlsx --stored-only -k usn -x "$RECORD" -s "$YEAR" -S "$START" -E "$END" \
    -r "$RELEASE" \
    || die "rating the Ubuntu Security Notices from the stored priorities ended with an error"
log "state rated from the stored priorities"

# The second pass looks up the CVEs that are not stored.
run ubuntu:rate-xlsx -k livepatch -x "$RECORD" -s "$YEAR-livepatch" -S "$START" -E "$END" \
    -r "$RELEASE" \
    || die "rating the Kernel Live Patch Security Notices ended with an error"
run ubuntu:rate-xlsx -k usn -x "$RECORD" -s "$YEAR" -S "$START" -E "$END" -r "$RELEASE" \
    || die "rating the Ubuntu Security Notices ended with an error"
unzip -qq -t "$RECORD" > /dev/null 2>&1 || die "the record is not a readable workbook"
log "state rated"


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
prune "$WORK_DIR/fortinet-*.tsv"
prune "$WORK_DIR/java-cve-*.tsv"

log "=== done"
