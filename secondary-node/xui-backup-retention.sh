#!/usr/bin/env bash
# ==============================================================================
# Script:         xui-backup-retention.sh
# Description:    Conservative retention policy manager for 3x-ui / Xray backups.
#                 Rotates validated encrypted incoming archives and purges
#                 expired quarantined/invalid items.
#
# Dependencies:   bash (>= 4.4), coreutils (sha256sum, date, sort, rm),
#                 findutils, util-linux (flock)
# Requirements:   Must not run as root; the service user needs write access
#                 to INCOMING_DIR, INVALID_DIR and LOG_FILE.
#
# Inputs:         - $INCOMING_DIR: directory with archives (*.tar.gz.gpg) and *.sha256
#                 - $INVALID_DIR:  directory with quarantined/malformed files
# Outputs:        - Appends structured logs to $LOG_FILE
#                 - Standard error on fatal validation failure
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

fail() {
  if [[ -w "$LOG_FILE" ]]; then
    printf '%s [ERROR] retention-v%s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$SCRIPT_VERSION" "$1" >> "$LOG_FILE"
  fi
  printf '%s [ERROR] retention-v%s: %s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$SCRIPT_VERSION" \
    "$1" >&2
  exit 1
}

# ------------------------------------------------------------------------------
# Pre-flight Checks
# ------------------------------------------------------------------------------
[[ $EUID -ne 0 ]] || fail 'must_not_run_as_root'
[[ -d "$INCOMING_DIR" ]] || fail 'incoming_directory_missing'
[[ -d "$INVALID_DIR" ]] || fail 'invalid_directory_missing'
[[ -f "$LOG_FILE" && -w "$LOG_FILE" ]] || fail 'receiver_log_missing_or_not_writable'
[[ -e "$LOCK_FILE" && ! -L "$LOCK_FILE" ]] || fail 'store_lock_missing_or_symlink'

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
mapfile -d '' -t all_archives < <(
  find "$INCOMING_DIR" -maxdepth 1 -type f -name 'xui-backup-*.tar.gz.gpg' -print0 \
    | sort -z
)

for archive in "${all_archives[@]}"; do
  [[ -f "$archive" ]] || continue
  base="$(basename -- "$archive")"
  sidecar="${archive}.sha256"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"

  if [[ ! -s "$sidecar" ]]; then
    log "quarantined reason=missing_or_empty_sidecar archive=$base"
    mv -f -- "$archive" "${INVALID_DIR}/${base}.${stamp}.orphaned" || true
    [[ -e "$sidecar" ]] && \
    mv -f -- "$sidecar" "${INVALID_DIR}/${base}.${stamp}.orphaned.sha256" || true
    continue
  fi

  if ! (cd "$INCOMING_DIR" && sha256sum -c --status -- "${base}.sha256"); then
    log "quarantined reason=checksum_failed archive=$base"
    mv -f -- "$archive" "${INVALID_DIR}/${base}.${stamp}.corrupt" || true
    mv -f -- "$sidecar" "${INVALID_DIR}/${base}.${stamp}.corrupt.sha256" || true
    continue
  fi
done

# Pass 2: Rotate verified archives exceeding the minimum guaranteed retention count
mapfile -d '' -t valid_archives < <(
  find "$INCOMING_DIR" -maxdepth 1 -type f -name 'xui-backup-*.tar.gz.gpg' -print0 \
    | sort -z
)

valid_count="${#valid_archives[@]}"
deletable=$(( valid_count - KEEP_MIN_ARCHIVES ))

if (( deletable > 0 )); then
  for archive in "${valid_archives[@]:0:deletable}"; do
    base="$(basename -- "$archive")"
    sidecar="${archive}.sha256"

    if [[ -z "$(find "$archive" -maxdepth 0 -mtime "+$KEEP_VALID_DAYS" -print -quit)" ]]; then
      log "preserved reason=within_retention_window archive=$base"
      continue
    fi

    rm -f -- "$archive" "$sidecar"
    log "removed reason=validated_and_expired archive=$base"
  done
else
  log "no_valid_archive_deletion count=$valid_count minimum=$KEEP_MIN_ARCHIVES"
fi

# ------------------------------------------------------------------------------
# Stage 2: Quarantine Purge
# ------------------------------------------------------------------------------
while IFS= read -r -d '' item; do
  rm -f -- "$item"
  log "removed_quarantine item=$(basename -- "$item")"
done < <(find "$INVALID_DIR" -maxdepth 1 -type f -mtime "+$KEEP_INVALID_DAYS" -print0)