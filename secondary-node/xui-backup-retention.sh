#!/usr/bin/env bash
# ==============================================================================
# Script:         xui-backup-retention.sh
# Description:    Conservative retention policy manager for 3x-ui / Xray backups.
#                 Rotates validated encrypted incoming archives and purges
#                 expired quarantined/invalid items.
#
# Dependencies:   bash (>= 4.4), coreutils (date, mv, rm, sha256sum, sort),
#                 findutils, util-linux (flock)
# Requirements:   Must run under dedicated unprivileged user (xbackup, EUID != 0).
#                 Requires read/write/exec (0700) on INCOMING_DIR and INVALID_DIR.
#                 Requires read/write (0600) on LOG_FILE and pre-created LOCK_FILE.
#
# Inputs:         None (filesystem discovery within pre-configured paths)
# Outputs:        - Appends structured logs to $LOG_FILE
#                 - Standard error on fatal validation failure
#
# Infrastructure Paths:
#   - Incoming store:   /opt/xui-backups/incoming       (0700 xbackup:xbackup)
#   - Quarantine store: /opt/xui-backups/invalid        (0700 xbackup:xbackup)
#   - Service log:      /opt/xui-backups/receiver.log   (0600 xbackup:xbackup)
#   - Service lock:     /opt/xui-backups/.store.lock    (0600 xbackup:xbackup)
#
# Exit Codes:
#   0   - Success (rotation completed or minimum archives retained)
#   1   - Validation error, lock timeout, missing access, or runtime error
#   130 - Interrupted by SIGINT
#   143 - Terminated by SIGTERM
# ==============================================================================

set -Eeuo pipefail
umask 077

command -v flock >/dev/null 2>&1 || {
  printf '%s\n' 'flock is required but was not found' >&2
  exit 1
}

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.3"

readonly INCOMING_DIR="/opt/xui-backups/incoming"
readonly INVALID_DIR="/opt/xui-backups/invalid"
readonly LOG_FILE="/opt/xui-backups/receiver.log"
readonly LOCK_FILE="/opt/xui-backups/.store.lock"
readonly LOCK_WAIT_SECONDS=7200
# Retention constraints
readonly KEEP_MIN_ARCHIVES=3
readonly KEEP_VALID_DAYS=21
readonly KEEP_INVALID_DAYS=7

# ------------------------------------------------------------------------------
# Logging & Error Handling
# ------------------------------------------------------------------------------
log() {
  printf '%s [INFO] retention-v%s: %s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$SCRIPT_VERSION" \
    "$1" >> "$LOG_FILE"
}

cleanup() {
  local -i exit_code=$?
  trap - EXIT ERR INT TERM
  flock -u 9 2>/dev/null || true
  exec 9>&- 2>/dev/null || true
  exit "$exit_code"
}

# shellcheck disable=SC2317,SC2329,SC2339 # Invoked indirectly via ERR trap
on_error() {
  local -i exit_code=$1
  local -i line_no=$2
  local command="$3"
  trap - ERR
  fail "unexpected_runtime_error line=$line_no exit_code=$exit_code cmd=\"$command\""
}

on_interrupt() {
  trap - INT TERM ERR
  log "interrupted reason=sigint_received" 2>/dev/null || true
  exit 130
}

on_terminate() {
  trap - INT TERM ERR
  log "interrupted reason=sigterm_received" 2>/dev/null || true
  exit 143
}

fail() {
  if [[ -w "$LOG_FILE" ]]; then
    printf '%s [ERROR] retention-v%s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$SCRIPT_VERSION" "$1" >> "$LOG_FILE" 2>/dev/null || true
  fi
  printf '%s [ERROR] retention-v%s: %s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$SCRIPT_VERSION" \
    "$1" >&2
  exit 1
}

trap cleanup EXIT
trap 'on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
trap on_interrupt INT
trap on_terminate TERM

main() {
  (( $# == 0 )) || fail 'cli_arguments_not_supported'
# ------------------------------------------------------------------------------
# Pre-flight Checks
# ------------------------------------------------------------------------------
  [[ $EUID -ne 0 ]] || fail 'must_not_run_as_root'
  [[ -d "$INCOMING_DIR" && -r "$INCOMING_DIR" && -w "$INCOMING_DIR" && -x "$INCOMING_DIR" ]] || fail 'incoming_directory_missing_or_no_access'
  [[ -d "$INVALID_DIR" && -r "$INVALID_DIR" && -w "$INVALID_DIR" && -x "$INVALID_DIR" ]] || fail 'invalid_directory_missing_or_no_access'
  [[ -f "$LOG_FILE" && -w "$LOG_FILE" ]] || fail 'receiver_log_missing_or_not_writable'
  [[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" && -w "$LOCK_FILE" ]] || fail 'store_lock_missing_or_unsafe'

  if ! exec 9>"$LOCK_FILE"; then
    fail "store_lock_open_failed lock_file=$LOCK_FILE"
  fi

  if ! flock -w "$LOCK_WAIT_SECONDS" 9; then
    fail "store_lock_timeout lock_file=$LOCK_FILE wait_seconds=$LOCK_WAIT_SECONDS"
  fi

# ------------------------------------------------------------------------------
# Stage 1: Sanitization & Rotation (Two-Pass Policy)
# ------------------------------------------------------------------------------

# Pass 1: Quarantine malformed or unverified archives across the entire incoming store
  local -a all_archives=()
  local archive base sidecar stamp
  mapfile -d '' -t all_archives < <(
    find "$INCOMING_DIR" -maxdepth 1 -type f -name 'xui-backup-*.tar.gz.gpg' -print0 \
    | sort -z
  )

  for archive in "${all_archives[@]}"; do
    [[ -f "$archive" ]] || continue
    base="${archive##*/}"
    sidecar="${archive}.sha256"
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"

    if [[ ! -s "$sidecar" ]]; then
      log "quarantined reason=missing_or_empty_sidecar archive=$base"
      mv -f -- "$archive" "${INVALID_DIR}/${base}.${stamp}.orphaned" || fail 'quarantine_failed_archive'
      if [[ -e "$sidecar" ]]; then
        mv -f -- "$sidecar" "${INVALID_DIR}/${base}.${stamp}.orphaned.sha256" || fail 'quarantine_failed_sidecar'
      fi
      continue
    fi

    if ! (cd -- "$INCOMING_DIR" && sha256sum -c --status -- "${base}.sha256"); then
      log "quarantined reason=checksum_failed archive=$base"
      mv -f -- "$archive" "${INVALID_DIR}/${base}.${stamp}.corrupt" || fail 'quarantine_failed_archive'
      mv -f -- "$sidecar" "${INVALID_DIR}/${base}.${stamp}.corrupt.sha256" || fail 'quarantine_failed_sidecar'
      continue
    fi
  done

# Pass 2: Rotate verified archives exceeding the minimum guaranteed retention count
  local -a valid_archives=()
  local -i valid_count deletable
  mapfile -d '' -t valid_archives < <(
    find "$INCOMING_DIR" -maxdepth 1 -type f -name 'xui-backup-*.tar.gz.gpg' -print0 \
    | sort -z
  )

  valid_count="${#valid_archives[@]}"
  deletable=$(( valid_count - KEEP_MIN_ARCHIVES ))

  if (( deletable > 0 )); then
    for archive in "${valid_archives[@]:0:deletable}"; do
      [[ -f "$archive" ]] || continue
      base="${archive##*/}"
      sidecar="${archive}.sha256"

      if [[ -z "$(find "$archive" -maxdepth 0 -mtime "+$KEEP_VALID_DAYS" -print -quit)" ]]; then
        log "preserved reason=within_retention_window archive=$base"
        continue
      fi

      rm -f -- "$archive"
      rm -f -- "$sidecar"
      log "removed reason=validated_and_expired archive=$base"
    done
  else
    log "no_valid_archive_deletion count=$valid_count minimum=$KEEP_MIN_ARCHIVES"
  fi

# ------------------------------------------------------------------------------
# Stage 2: Quarantine Purge
# ------------------------------------------------------------------------------
  local item
  while IFS= read -r -d '' item; do
    rm -f -- "$item"
    log "removed_quarantine item=${item##*/}"
  done < <(find "$INVALID_DIR" -maxdepth 1 -type f -mtime "+$KEEP_INVALID_DAYS" -print0)
}

main "$@"