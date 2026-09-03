#!/usr/bin/env bash
# ==============================================================================
# Script:        xui-backup-health-v1.4.sh
# Description:   Read-only health & SLA verification for X-UI backup archives.
# Dependencies:  bash (>= 4.4), coreutils (find, sort, date, stat, sha256sum, grep, tail)
# Inputs:        None (operates on configured filesystem paths)
# Outputs:       Single/multi-line key-value status strings to stdout
# Exit Codes:    0 = OK (SLA & integrity verified)
#                2 = CRITICAL (missing files, stale backup, checksum mismatch, etc.)
# ==============================================================================

set -Eeuo pipefail

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.4"
readonly INCOMING_DIR="/opt/xui-backups/incoming"
readonly LOG_FILE="/opt/xui-backups/receiver.log"
readonly MAX_BACKUP_AGE_HOURS=26

# ------------------------------------------------------------------------------
# Error Handling
# ------------------------------------------------------------------------------
critical() {
  local last_log="NONE"

  if [[ -r "$LOG_FILE" ]]; then
    last_log=$(grep -E 'delivery_verified_ok|idempotent_delivery_skipped|orphan_archive_sidecar_repaired' "$LOG_FILE" 2>/dev/null | tail -n 1 || true)
    [[ -n "$last_log" ]] || last_log="NONE"
  fi

  printf 'STATUS=CRITICAL version=%s %s\n' "$SCRIPT_VERSION" "$1"
  printf 'LAST_RECEIVER_LOG=%s\n' "$last_log"
  exit 2
}

parse_backup_timestamp() {
  local archive_base="$1"
  local raw_date raw_time iso_date iso_time

  if [[ "$archive_base" =~ xui-backup-([0-9]{8})T([0-9]{6})Z- ]]; then
    raw_date="${BASH_REMATCH[1]}"
    raw_time="${BASH_REMATCH[2]}"
    iso_date="${raw_date:0:4}-${raw_date:4:2}-${raw_date:6:2}"
    iso_time="${raw_time:0:2}:${raw_time:2:2}:${raw_time:4:2}"
    date -u -d "${iso_date}T${iso_time}Z" +%s
  else
    return 1
  fi
}

# ------------------------------------------------------------------------------
# Pre-flight Checks
# ------------------------------------------------------------------------------
# Read-only; may run as xbackup or root, provided INCOMING_DIR/LOG_FILE are readable.
[[ -d "$INCOMING_DIR" && -r "$INCOMING_DIR" ]] || critical 'reason=incoming_directory_missing_or_unreadable'

# ------------------------------------------------------------------------------
# Archive Discovery & Selection
# ------------------------------------------------------------------------------
# Read null-delimited sorted list of matching archives into an indexed array
mapfile -d '' -t archives < <(
  find "$INCOMING_DIR" -maxdepth 1 -type f -name 'xui-backup-*.tar.gz.gpg' -print0 | sort -z
)

(( ${#archives[@]} > 0 )) || critical 'message="no_archives_found"'
# Pick the newest lexicographically sorted archive and its sidecar
latest="${archives[${#archives[@]}-1]}"
sidecar="${latest}.sha256"

# ------------------------------------------------------------------------------
# Age & SLA Verification
# ------------------------------------------------------------------------------
now=$(date -u +%s)
archive_base="$(basename -- "$latest")"

backup_epoch="$(parse_backup_timestamp "$archive_base")" ||
  critical "archive=$archive_base reason=unparseable_timestamp"

age_seconds=$(( now - backup_epoch ))
 
 if (( age_seconds < 0 )); then
  age_seconds=0
 fi
 
 age_hours=$(( age_seconds / 3600 ))

 if (( age_seconds > MAX_BACKUP_AGE_HOURS * 3600 )); then
  critical "archive=$archive_base reason=\"AGE_EXCEEDED\" age_hours=$age_hours max_age_hours=$MAX_BACKUP_AGE_HOURS"
 fi

# ------------------------------------------------------------------------------
# Integrity & Checksum Verification
# ------------------------------------------------------------------------------
[[ -s "$latest" && -s "$sidecar" ]] || \
  critical "archive=$archive_base reason=archive_or_sidecar_missing_or_empty"

# Subshell ensures working directory remains unchanged in the main execution context
(cd "$INCOMING_DIR" && sha256sum -c --status -- "$(basename -- "$sidecar")") || \
  critical "archive=$archive_base reason=\"CHECKSUM_FAIL\""

archive_bytes="$(stat -c %s -- "$latest")" || \
  critical "archive=$archive_base reason=archive_vanished_during_check"

# ------------------------------------------------------------------------------
# Receiver Log Audit
# ------------------------------------------------------------------------------
last_log="NONE"
if [[ -r "$LOG_FILE" ]]; then
  last_log=$(grep -E 'delivery_verified_ok|idempotent_delivery_skipped|orphan_archive_sidecar_repaired' \
    "$LOG_FILE" 2>/dev/null | tail -n 1 || true)

  if [[ -z "$last_log" ]]; then
    last_log="NONE"
  fi
fi

# ------------------------------------------------------------------------------
# Report / Output
# ------------------------------------------------------------------------------
printf 'STATUS=OK version=%s archive=%s bytes=%s age_hours=%s checksum=OK\n' \
  "$SCRIPT_VERSION" \
  "$archive_base" \
  "$archive_bytes" \
  "$age_hours"

printf 'LAST_RECEIVER_LOG=%s\n' "$last_log"