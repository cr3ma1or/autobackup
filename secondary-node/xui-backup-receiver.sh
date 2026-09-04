#!/usr/bin/env bash
### ==============================================================================
### Script:         xui-backup-receiver.sh
### Description:    SSH forced-command receiver for automated, verified backup delivery.
###                 Ingests payload stream over STDIN, validates SHA-256 integrity,
###                 and atomically publishes archive and sidecar files.
### Dependencies:   bash (>= 4.4), coreutils (cut, date, df, head, sha256sum, sort, stat),
###                 findutils (find), util-linux (flock)
### Requirements:   Must run under dedicated unprivileged user (xbackup, EUID != 0).
###                 Executed strictly via authorized_keys command="..." restriction.
###                 Requires read/write/exec (0700) on INCOMING_DIR and INVALID_DIR.
###                 Requires read/write (0600) on LOG_FILE and pre-created LOCK_FILE.
### Inputs:         - Environment: SSH_ORIGINAL_COMMAND ("receive <name> <sha256> <size>")
###                 - STDIN: raw encrypted archive stream
### Outputs:        - STDOUT: "OK <name> <sha256> <size>" on success, "ERROR <CODE>" on failure
###                 - Appends structured audit logs to $LOG_FILE
###                 - Standard error on runtime rejection
### Infrastructure Paths:
###   - Incoming store:   /opt/xui-backups/incoming       (0700 xbackup:xbackup)
###   - Quarantine store: /opt/xui-backups/invalid        (0700 xbackup:xbackup)
###   - Service log:      /opt/xui-backups/receiver.log   (0600 xbackup:xbackup)
###   - Service lock:     /opt/xui-backups/.store.lock    (0600 xbackup:xbackup)
### Exit Codes:
###   0   - Success (delivery verified or idempotent delivery acknowledged)
###   1   - Validation error, protocol failure, capacity exhaustion, or lock busy
###   130 - Interrupted by SIGINT
###   143 - Terminated by SIGTERM
### ==============================================================================

set -Eeuo pipefail
umask 077

command -v flock >/dev/null 2>&1 || {
  printf '%s\n' 'flock is required but was not found' >&2
  exit 1
}

# ------------------------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.4"
readonly BASE_DIR="/opt/xui-backups"
readonly INCOMING_DIR="${BASE_DIR}/incoming"
readonly INVALID_DIR="${BASE_DIR}/invalid"
readonly LOG_FILE="${BASE_DIR}/receiver.log"
readonly LOCK_FILE="${BASE_DIR}/.store.lock"
readonly EXPECTED_USER="xbackup"
readonly SCRIPT_NAME="${0##*/}"
readonly MAX_BYTES=$((2 * 1024 * 1024 * 1024)) # 2 GiB upload threshold
readonly MAX_QUARANTINE_FILES=14
readonly MAX_DISK_USAGE_PCT=90
readonly MIN_FREE_KB=512000            # 500 MiB floor
readonly SAFETY_BUFFER_KB=102400       # 100 MiB per-upload buffer
readonly MAX_UPLOADS_PER_24H=24
readonly READ_TIMEOUT_SECONDS=300
readonly LOG_FILE_WARN_BYTES=$((100 * 1024 * 1024)) # 100 MiB

# ------------------------------------------------------------------------------
# 2. Helper Functions & Error Handling
# ------------------------------------------------------------------------------
require_commands() {
  local command_name

for command_name in \
  awk \
  chmod \
  cmp \
  cut \
  date \
  df \
  find \
  flock \
  head \
  id \
  mktemp \
  mv \
  rm \
  sha256sum \
  sort \
  stat \
  timeout \
  wc; do
    command -v "$command_name" >/dev/null 2>&1 ||
      fail "MISSING_DEPENDENCY" "command=$command_name"
  done
}

log() {
  local level="$1"
  local message="$2"
  local timestamp
  local line

  if [[ "$level" == "DEBUG" && "${VERBOSE:-0}" -ne 1 ]]; then
    return 0
  fi

  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)" ||
  timestamp="1970-01-01T00:00:00Z"

  line="$(printf '%s [%s] [%s v%s pid=%s] %s' \
  "$timestamp" "$level" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$$" "$message")"

  if ! printf '%s\n' "$line" >> "$LOG_FILE"; then
    printf '%s\n' "$line" >&2
    return 1
  fi
}

fail() {
  local code="$1"
  local message="${2:-$code}"

  if [[ ! "$code" =~ ^[A-Z][A-Z0-9_]{0,63}$ ]]; then
    code="INTERNAL_ERROR"
  fi

  log ERROR "code=$code $message" || true

  printf 'ERROR %s\n' "$code"
  exit 1
}

# Removes oldest quarantined files when count exceeds MAX_QUARANTINE_FILES
prune_quarantine() {
  local manifest
  local count
  local f
  local remove_count
  local -a old_invalid=()

  if ! manifest="$(mktemp "${BASE_DIR}/.prune_manifest.XXXXXX")"; then
    fail "QUARANTINE_FAILED" "reason=manifest_creation_failed"
  fi

  if ! find "$INVALID_DIR" -maxdepth 1 -type f -printf '%T@\t%p\0' |
      sort -z -n |
      cut -z -f2- > "$manifest"; then
    rm -f -- "$manifest" || true
    fail "QUARANTINE_LISTING_FAILED" "directory=$INVALID_DIR"
  fi

  if ! mapfile -d '' -t old_invalid < "$manifest"; then
    rm -f -- "$manifest" || true
    fail "QUARANTINE_MANIFEST_READ_FAILED" "manifest=$manifest"
  fi

  rm -f -- "$manifest" ||
    fail "QUARANTINE_MANIFEST_CLEANUP_FAILED" "manifest=$manifest"

  count=${#old_invalid[@]}
  if (( count <= MAX_QUARANTINE_FILES )); then
    return 0
  fi

  remove_count=$((count - MAX_QUARANTINE_FILES))
  for f in "${old_invalid[@]:0:remove_count}"; do
    rm -f -- "$f" ||
    fail "QUARANTINE_PRUNE_FAILED" "file=$f"
  done
}

quarantine_part() {
  local suffix="$1"
  local target

  if [[ ! -e "$part" ]]; then
    return 0
  fi

  if ! target="$(mktemp "${INVALID_DIR}/.${name}.${suffix}.XXXXXX")"; then
    fail "QUARANTINE_TARGET_CREATE_FAILED" "archive=$name suffix=$suffix"
  fi

  if ! mv -f -- "$part" "$target"; then
    rm -f -- "$target" || true
    fail "QUARANTINE_MOVE_FAILED" "archive=$name suffix=$suffix"
  fi

  prune_quarantine
}

get_storage_metrics() {
  local df_output

  if ! df_output="$(df -Pk "$BASE_DIR" 2>/dev/null)"; then
    return 1
  fi

  # Склеиваем перенесённые строки (длинное имя ФС), затем берём последнюю
  # строку вывода -- это гарантированно строка данных, а не заголовок.
  awk '
    NR > 1 { buf = (buf ? buf " " $0) : $0 }
    END {
      n = split(buf, f, /[ \t]+/)
      if (n < 5) { exit 1 }
      pct = f[n-1]
      avail = f[n-2]
      gsub("%", "", pct)
      print pct, avail
    }
  ' <<< "$df_output"
}


check_storage_headroom() {
  local metrics
  local usage_pct
  local avail_kb

  if ! metrics="$(get_storage_metrics)"; then
    fail "DISK_USAGE_UNAVAILABLE" "base_dir=$BASE_DIR"
  fi

  if ! read -r usage_pct avail_kb <<< "$metrics"; then
    fail "DISK_USAGE_INVALID" "metrics=$metrics"
  fi

  if [[ ! "$usage_pct" =~ ^[0-9]+$ || ! "$avail_kb" =~ ^[0-9]+$ ]]; then
    fail "DISK_USAGE_INVALID" "usage_pct=$usage_pct avail_kb=$avail_kb"
  fi

  if (( usage_pct >= MAX_DISK_USAGE_PCT || avail_kb < MIN_FREE_KB )); then
    fail "STORAGE_EXHAUSTED" "usage_pct=$usage_pct avail_kb=$avail_kb"
  fi

}

check_rate_limit() {
  local recent_count

  if ! recent_count="$(
    find "$INCOMING_DIR" -maxdepth 1 -type f \
      -name 'xui-backup-*.tar.gz.gpg' \
      -mmin -1440 -print |
      wc -l
  )"; then
    fail "RATE_LIMIT_UNAVAILABLE" "directory=$INCOMING_DIR"
  fi

  if [[ ! "$recent_count" =~ ^[0-9]+$ ]]; then
    fail "RATE_LIMIT_INVALID" "recent_count=$recent_count"
  fi

  if (( recent_count >= MAX_UPLOADS_PER_24H )); then
    fail "RATE_LIMIT" "count_24h=$recent_count"
  fi
}

# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------
main() {
  local name expected declared_size
  local original command_regex storage_metrics _usage_pct
  local -i needed_kb avail_kb
  local part="" part_hash="" final="" hash_file=""
  local final_size actual_size actual expected_sidecar

  # ----------------------------------------------------------------------------
  # 3. Environment & Permission Checks
  # ----------------------------------------------------------------------------
  require_commands

  if [[ "$EUID" -eq 0 ]]; then
    fail "REFUSING_ROOT_EXECUTION" "euid=$EUID"
  fi

  if [[ "$(id -un)" != "$EXPECTED_USER" ]]; then
    fail "UNEXPECTED_EXECUTION_USER" \
      "expected_user=$EXPECTED_USER actual_user=$(id -un)"
  fi

  if [[ ! -d "$BASE_DIR" || ! -d "$INCOMING_DIR" || ! -d "$INVALID_DIR" ]]; then
    fail "STORAGE_DIRECTORY_MISSING" \
      "base_dir=$BASE_DIR incoming_dir=$INCOMING_DIR invalid_dir=$INVALID_DIR"
  fi

  if [[ ! -w "$INCOMING_DIR" || ! -x "$INCOMING_DIR" ]]; then
    fail "INCOMING_DIRECTORY_NOT_WRITABLE" "directory=$INCOMING_DIR"
  fi

  if [[ ! -w "$INVALID_DIR" || ! -x "$INVALID_DIR" ]]; then
    fail "INVALID_DIRECTORY_NOT_WRITABLE" "directory=$INVALID_DIR"
  fi

  if [[ -L "$LOG_FILE" || ! -f "$LOG_FILE" || ! -w "$LOG_FILE" ]]; then
    fail "LOG_FILE_UNAVAILABLE" "log_file=$LOG_FILE"
  fi

  local log_size
  if [[ -f "$LOG_FILE" ]]; then
    log_size="$(stat -c '%s' -- "$LOG_FILE" 2>/dev/null || echo 0)"
    if (( log_size > LOG_FILE_WARN_BYTES )); then
      log WARN "log_file_large size_bytes=$log_size threshold_bytes=$LOG_FILE_WARN_BYTES"
    fi
  fi

  check_storage_headroom

  # ----------------------------------------------------------------------------
  # 4. Command Parsing & Pre-flight Validation
  # ----------------------------------------------------------------------------
  original="${SSH_ORIGINAL_COMMAND:-}"
  command_regex='^receive[[:space:]]+(xui-backup-[0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9]+\.tar\.gz\.gpg)[[:space:]]+([a-f0-9]{64})[[:space:]]+([1-9][0-9]*)$'

  if [[ "$original" =~ $command_regex ]]; then
    name="${BASH_REMATCH[1]}"
    expected="${BASH_REMATCH[2]}"
    declared_size="${BASH_REMATCH[3]}"
  else
    fail "INVALID_COMMAND" "reason=invalid_requested_command"
  fi

  if (( declared_size > MAX_BYTES )); then
    fail "INVALID_SIZE" "archive=$name declared_size=$declared_size max_bytes=$MAX_BYTES"
  fi

  # Pre-check: declared payload plus 100 MiB safety buffer.
  if ! storage_metrics="$(get_storage_metrics)"; then
    fail "DISK_SPACE_UNAVAILABLE" "base_dir=$BASE_DIR"
  fi

  if ! read -r _usage_pct avail_kb <<< "$storage_metrics"; then
    fail "DISK_SPACE_INVALID" "metrics=$storage_metrics"
  fi

  if [[ ! "$avail_kb" =~ ^[0-9]+$ ]]; then
    fail "DISK_SPACE_INVALID" "avail_kb=$avail_kb"
  fi

  needed_kb=$(((declared_size + 1023) / 1024 + SAFETY_BUFFER_KB))

  # ----------------------------------------------------------------------------
  # Pre-flight Capacity Verification (теперь реально работает: avail_kb/needed_kb
  # заполнены выше, в том же скоупе, без повторного local)
  # ----------------------------------------------------------------------------
  if (( avail_kb < needed_kb )); then
    fail "STORAGE_EXHAUSTED" "available_kb=$avail_kb needed_kb=$needed_kb"
  fi

  if ! exec 9>"$LOCK_FILE"; then
    fail "RECEIVER_LOCK_OPEN_FAILED" "lock_file=$LOCK_FILE"
  fi

  if ! flock -n 9; then
    fail "RECEIVER_BUSY" "lock_file=$LOCK_FILE"
  fi

  # ----------------------------------------------------------------------------
  # Target Paths & Temporary Allocation
  # ----------------------------------------------------------------------------
  if ! part="$(mktemp "${INCOMING_DIR}/.tmp_recv.XXXXXX")"; then
    fail "TEMPORARY_FILE_CREATION_FAILED" "archive=$name"
  fi

  part_hash="${part}.sha256"
  final="${INCOMING_DIR}/${name}"   # name теперь реально заполнено
  hash_file="${final}.sha256"

cleanup() {
  local -i exit_code=$?
  trap - EXIT ERR INT TERM HUP
  flock -u 9 2>/dev/null || true
  exec 9>&- 2>/dev/null || true
  rm -f -- "${part:-}" "${part_hash:-}" 2>/dev/null || true
  exit "$exit_code"
}

# shellcheck disable=SC2317,SC2329,SC2339 # Invoked indirectly via ERR trap
on_error() {
  local -i exit_code=$1
  local -i line_no=$2
  local failed_cmd="$3"
  trap - ERR
  fail "UNEXPECTED_RUNTIME_ERROR" "line=$line_no exit_code=$exit_code cmd=\"$failed_cmd\""
}

on_interrupt() {
  trap - INT TERM ERR HUP
  log WARN "interrupted reason=sigint_received archive=${name:-unknown}" 2>/dev/null || true
  exit 130
}

on_terminate() {
  local signal_name="${1:-TERM}"
  trap - INT TERM ERR HUP
  log WARN "interrupted reason=sig${signal_name,,}_received archive=${name:-unknown}" 2>/dev/null || true
  exit 143
}

trap cleanup EXIT
trap 'on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
trap on_interrupt INT
trap 'on_terminate TERM' TERM
trap 'on_terminate HUP'  HUP

# ----------------------------------------------------------------------------
# Idempotent Delivery Check & Stream Drainage
# ----------------------------------------------------------------------------
expected_sidecar="$(printf '%s  %s\n' "$expected" "$name")"

if [[ -e "$final" || -e "$hash_file" ]]; then
  if [[ -f "$final" && -f "$hash_file" ]]; then
    if ! final_size="$(stat -c '%s' -- "$final")"; then
      fail "EXISTING_ARCHIVE_STAT_FAILED" "archive=$name"
    fi

    if [[ "$final_size" == "$declared_size" ]] &&
       printf '%s\n' "$expected_sidecar" | cmp -s - "$hash_file" &&
       printf '%s\n' "$expected_sidecar" |
         (cd "$INCOMING_DIR" && sha256sum -c --status -); then

      # Drain the retransmitted payload before returning the idempotent result.
      head -c "$declared_size" > /dev/null || true

      log INFO \
        "idempotent_delivery_skipped archive=$name bytes=$declared_size sha256=$expected"
      printf 'OK %s %s %s\n' "$name" "$expected" "$declared_size"
      exit 0
    fi

    fail "NAME_COLLISION" \
      "archive=$name declared_sha256=$expected declared_size=$declared_size"
  fi

  if [[ -f "$final" && ! -e "$hash_file" ]]; then
    if ! final_size="$(stat -c '%s' -- "$final")"; then
      fail "EXISTING_ARCHIVE_STAT_FAILED" "archive=$name"
    fi

    if [[ "$final_size" != "$declared_size" ]]; then
      fail "NAME_COLLISION" \
        "archive=$name reason=orphan_archive_size_mismatch existing_size=$final_size declared_size=$declared_size"
    fi

    if ! printf '%s\n' "$expected_sidecar" |
        (cd "$INCOMING_DIR" && sha256sum -c --status -); then
      fail "NAME_COLLISION" \
        "archive=$name reason=orphan_archive_checksum_mismatch"
    fi

    if ! printf '%s\n' "$expected_sidecar" > "$part_hash"; then
      fail "SIDECAR_WRITE_FAILED" \
        "archive=$name reason=orphan_archive_repair"
    fi

    if ! chmod 0600 "$part_hash"; then
      fail "ARCHIVE_PERMISSION_SET_FAILED" \
        "artifact=sidecar archive=$name reason=orphan_archive_repair"
    fi

    if ! mv -f -- "$part_hash" "$hash_file"; then
      fail "PUBLISH_FAILED" \
        "artifact=sidecar archive=$name reason=orphan_archive_repair"
    fi

    # Drain the retransmitted payload before returning the repaired result.
    head -c "$declared_size" > /dev/null || true

    log WARN \
      "orphan_archive_sidecar_repaired archive=$name bytes=$declared_size sha256=$expected"
    printf 'OK %s %s %s\n' "$name" "$expected" "$declared_size"
    exit 0
  fi

  if [[ ! -e "$final" && -f "$hash_file" ]]; then
    if ! rm -f -- "$hash_file"; then
      fail "ORPHAN_SIDECAR_CLEANUP_FAILED" "sidecar=$hash_file"
    fi

    log WARN "orphan_sidecar_removed sidecar=$hash_file"
  else
    fail "NAME_COLLISION" \
      "archive=$name reason=unexpected_existing_file_type"
  fi
fi

# Applies only to genuinely new archive publication.
check_rate_limit

# ------------------------------------------------------------------------------
# 7. Stream Ingestion & Verification
# ------------------------------------------------------------------------------
# Read payload from STDIN (с таймаутом на случай зависшего клиента,
# который держит flock и слот rate-limit неопределённо долго)
if ! timeout "${READ_TIMEOUT_SECONDS}" head -c "$declared_size" > "$part"; then
  quarantine_part 'partial'
  fail "READ_FAILED" "archive=$name reason=timeout_or_short_read"
fi

# Verify actual received byte count
if ! actual_size="$(stat -c '%s' -- "$part")"; then
  quarantine_part 'stat_failed'
  fail "TEMPORARY_ARCHIVE_STAT_FAILED" "archive=$name"
fi

if [[ "$actual_size" != "$declared_size" ]]; then
  quarantine_part 'partial'
  fail "SIZE_MISMATCH" \
  "archive=$name expected_size=$declared_size actual_size=$actual_size"
fi

# Verify SHA256 checksum
if ! actual="$(sha256sum -- "$part" | awk '{print $1}')"; then
  quarantine_part 'hash_failed'
  fail "CHECKSUM_CALCULATION_FAILED" "archive=$name"
fi

if [[ ! "$actual" =~ ^[a-f0-9]{64}$ ]]; then
  quarantine_part 'hash_invalid'
  fail "CHECKSUM_OUTPUT_INVALID" "archive=$name actual=$actual"
fi

if [[ "$actual" != "$expected" ]]; then
  quarantine_part 'badsha256'
  fail "CHECKSUM_MISMATCH" "archive=$name expected=$expected actual=$actual"
fi

# ------------------------------------------------------------------------------
# 8. Finalization
# ------------------------------------------------------------------------------
if ! printf '%s  %s\n' "$expected" "$name" > "$part_hash"; then
  fail "SIDECAR_WRITE_FAILED" "archive=$name"
fi

if ! chmod 0600 "$part" "$part_hash"; then
  fail "ARCHIVE_PERMISSION_SET_FAILED" "archive=$name"
fi

 if ! mv -f -- "$part_hash" "$hash_file"; then
   fail "PUBLISH_FAILED" "artifact=sidecar archive=$name"
 fi

 if ! mv -f -- "$part" "$final"; then
   fail "PUBLISH_FAILED" "artifact=archive archive=$name"
 fi

trap - EXIT

log INFO "delivery_verified_ok archive=$name bytes=$declared_size sha256=$expected"
printf 'OK %s %s %s\n' "$name" "$expected" "$declared_size"
}

main "$@"