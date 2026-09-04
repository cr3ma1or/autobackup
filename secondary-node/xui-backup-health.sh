#!/usr/bin/env bash
# ==============================================================================
# Script:        xui-backup-health-v1.4.sh
# Description:   Read-only health & SLA verification for X-UI backup archives.
# Dependencies:  bash (>= 4.4), coreutils (find, sort, date, stat, sha256sum, grep, tail)
# Inputs:        None (operates on configured filesystem paths)
# Outputs:       Single/multi-line key-value status strings to stdout
# Exit Codes:    0 = OK (SLA & integrity verified)
#                1 = Usage error (invalid arguments)
#                2 = CRITICAL (missing files, stale backup, checksum mismatch, etc.)
# ==============================================================================

set -Eeuo pipefail

# ------------------------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.4"
readonly INCOMING_DIR="/opt/xui-backups/incoming"
readonly LOG_FILE="/opt/xui-backups/receiver.log"
readonly MAX_BACKUP_AGE_HOURS=26

# ------------------------------------------------------------------------------
# Logging & Error Traps
# ------------------------------------------------------------------------------
get_last_receiver_log() {
  if [[ -r "$LOG_FILE" ]]; then
    local line
    line=$(grep -E 'delivery_verified_ok|idempotent_delivery_(skipped|ok)|orphan_archive_sidecar_repaired' "$LOG_FILE" 2>/dev/null | tail -n 1 || true)
    printf '%s' "${line:-NONE}"
  else
    printf 'NONE'
  fi
}

critical() {
  local last_log
  last_log="$(get_last_receiver_log 2>/dev/null || printf 'NONE')"

  printf 'STATUS=CRITICAL version=%s %s\n' "$SCRIPT_VERSION" "$1"
  printf 'LAST_RECEIVER_LOG=%s\n' "$last_log"
  exit 2
}

# shellcheck disable=SC2317,SC2329,SC2339
on_error() {
  local exit_code="$1" line="$2" cmd="$3"
  trap - ERR

  local last_log
  last_log="$(get_last_receiver_log 2>/dev/null || printf 'NONE')"

  printf 'STATUS=CRITICAL version=%s reason=unexpected_error line=%s cmd="%s" exit_code=%s\n' \
    "$SCRIPT_VERSION" "$line" "$cmd" "$exit_code"
  printf 'LAST_RECEIVER_LOG=%s\n' "$last_log"
  exit 2
}
trap 'on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
trap 'critical "reason=interrupted"' INT TERM


parse_backup_timestamp() {
  local archive_base="$1"
  local raw_date raw_time iso_date iso_time

  if [[ "$archive_base" =~ ^xui-backup-([0-9]{8})T([0-9]{6})Z- ]]; then
    raw_date="${BASH_REMATCH[1]}"
    raw_time="${BASH_REMATCH[2]}"
    iso_date="${raw_date:0:4}-${raw_date:4:2}-${raw_date:6:2}"
    iso_time="${raw_time:0:2}:${raw_time:2:2}:${raw_time:4:2}"
    date -u -d "${iso_date}T${iso_time}Z" +%s 2>/dev/null
  else
    return 1
  fi
}

usage() {
  cat <<EOF
Usage: ${0##*/} [--help|--version]

Read-only health & SLA verification for X-UI backup archives.

Options:
  -h, --help     Show this help message and exit
  -v, --version  Show script version and exit
EOF
  exit 0
}

version() {
  printf '%s version %s\n' "${0##*/}" "$SCRIPT_VERSION"
  exit 0
}

check_dependencies() {
  local cmd
  for cmd in find sort date stat sha256sum grep tail; do
    command -v -- "$cmd" >/dev/null 2>&1 || critical "reason=missing_dependency cmd=$cmd"
  done
}

check_bash_version() {
  if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    critical "reason=bash_too_old current=$BASH_VERSION required=4.4+"
  fi
}

# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------
main() {
  local latest sidecar now archive_base backup_epoch age_seconds age_hours archive_bytes last_log
  local -a archives=()
  if (( $# == 0 )); then
    : # Штатный запуск без аргументов
  elif [[ "$1" == "-h" || "$1" == "--help" ]] && (( $# == 1 )); then
    usage
  elif [[ "$1" == "-v" || "$1" == "--version" ]] && (( $# == 1 )); then
    version
  else
    printf 'Invalid argument(s): %s\nRun "%s --help" for details.\n' "$*" "${0##*/}" >&2
    exit 1
  fi

  check_dependencies
  check_bash_version

# --------------------------------------------------------------------------
# Pre-flight Checks
# --------------------------------------------------------------------------
# Read-only; may run as xbackup or root, provided INCOMING_DIR/LOG_FILE are readable.
  [[ -d "$INCOMING_DIR" && -r "$INCOMING_DIR" && -x "$INCOMING_DIR" ]] || critical 'reason=incoming_directory_missing_or_unreadable'

# ------------------------------------------------------------------------------
# Archive Discovery & Selection
# ------------------------------------------------------------------------------
# Read null-delimited sorted list of matching archives into an indexed array
  mapfile -d '' -t archives < <(
  find "$INCOMING_DIR" -maxdepth 1 -type f -name 'xui-backup-*.tar.gz.gpg' -print0 | sort -z
  )

  (( ${#archives[@]} > 0 )) || critical 'reason=no_archives_found'
# Pick the newest lexicographically sorted archive and its sidecar
  latest="${archives[${#archives[@]}-1]}"
  sidecar="${latest}.sha256"

# ------------------------------------------------------------------------------
# Age & SLA Verification
# ------------------------------------------------------------------------------
  now=$(date -u +%s)
  archive_base="${latest##*/}"

  backup_epoch="$(parse_backup_timestamp "$archive_base")" || \
    critical "archive=$archive_base reason=unparseable_timestamp"

  [[ "$backup_epoch" =~ ^[0-9]+$ ]] || \
    critical "archive=$archive_base reason=invalid_timestamp_epoch"

  age_seconds=$(( now - backup_epoch ))

  if (( age_seconds < 0 )); then
    age_seconds=0
  fi

  age_hours=$(( age_seconds / 3600 ))

  if (( age_seconds > MAX_BACKUP_AGE_HOURS * 3600 )); then
    critical "archive=$archive_base reason=age_exceeded age_hours=$age_hours age_seconds=$age_seconds max_age_hours=$MAX_BACKUP_AGE_HOURS"
  fi

# ------------------------------------------------------------------------------
# Integrity & Checksum Verification
# ------------------------------------------------------------------------------
  [[ -s "$latest" && -s "$sidecar" ]] || \
    critical "archive=$archive_base reason=archive_or_sidecar_missing_or_empty"

# Subshell ensures working directory remains unchanged in the main execution context
  (cd -- "$INCOMING_DIR" && sha256sum -c --status -- "${sidecar##*/}") || \
    critical "archive=$archive_base reason=checksum_fail"

  archive_bytes="$(stat -c %s -- "$latest")" || \
    critical "archive=$archive_base reason=archive_vanished_during_check"

  [[ "$archive_bytes" =~ ^[0-9]+$ ]] || \
    critical "archive=$archive_base reason=invalid_archive_size"

# ------------------------------------------------------------------------------
# Receiver Log Audit
# ------------------------------------------------------------------------------
  last_log="$(get_last_receiver_log 2>/dev/null || printf 'NONE')"

# --------------------------------------------------------------------------
  # Report / Output
  # --------------------------------------------------------------------------
  printf 'STATUS=OK version=%s archive=%s bytes=%s age_hours=%s checksum=OK\n' \
    "$SCRIPT_VERSION" \
    "$archive_base" \
    "$archive_bytes" \
    "$age_hours"

  printf 'LAST_RECEIVER_LOG=%s\n' "$last_log"
  exit 0
}

main "$@"