#!/usr/bin/env bash
# ==============================================================================
# Name:        xui-backup
# Version:     2.10
# Example:     /usr/local/bin/xui-backup --dry-run
# Supported:   GNU/Linux, Bash >= 4.4, GNU coreutils, GNU tar, Systemd >= 245
# Description: 3x-ui encrypted SQLite backup + JSON payload export with
#              manifest hashing, local retention rotation, weekly restore tests,
#              Telegram notifications, and non-blocking verified off-site transfer.
#              Temp files on physical disk; adaptive disk pre-flight; optional JSON export; 
#              non-blocking Telegram; min-archive-safe rotation.
# Author:      cr3ma1or
# Last Change: 2026-08-30
# License:     MIT License
#
# Backup Format:
# - Payload: SQLite backup, manifest.json, optional 3xui_export.json
# - Archive: deterministic tar + gzip + GPG symmetric AES-256 encryption
# - Integrity: SHA-256 sidecar plus decrypt/extract/SQLite verification
#
# Operational Notes:
# - --dry-run validates configuration and simulates retention only.
# - --dry-run does not create an archive, upload to Telegram/off-site storage,
#   prune archives, or reap stale artifacts.
# - A successful run verifies the newly created archive before delivery and rotation.
# - Restore testing requires the same BACKUP_PASSPHRASE used for archive creation.
#
# CLI Flags:
#   --dry-run   Validate environment/config and simulate rotate(); skip backup/send
#   --no-prune  Create and deliver backup, but skip archive deletion in rotate()
#   -v, --verbose  Enable DEBUG-level log output
#   -h, --help  Show usage message and exit
#
# Environment Variables (.env / backup-transfer.env):
#   BACKUP_PASSPHRASE      (string, required, >= 32 chars) - GPG symmetric encryption key
#   SEND_TELEGRAM          (0|1, default: 0) - Enable/disable Telegram alerts
#   TG_BOT_TOKEN           (string) - Telegram Bot token (required if SEND_TELEGRAM=1)
#   TG_CHAT_ID             (int) - Target Telegram chat/channel ID
#   TG_PROXY_URL           (url, optional) - Proxy for Telegram API requests
#   EXPORT_JSON            (0|1, default: 1) - Export human-readable table dump
#   TRANSFER_ENABLED       (0|1, default: 0) - Off-site SSH transport switch
#   TRANSFER_HOST          (string) - Remote backup destination hostname/IP
#   TRANSFER_USER          (string) - Remote unprivileged SSH receiver username
#   TRANSFER_PORT          (int, default: 22) - Remote SSH port (1-65535)
#   TRANSFER_KEY           (path) - Path to dedicated SSH private key (0600)
#   TRANSFER_KNOWN_HOSTS   (path) - Path to pinned known_hosts file (0644/0600)
#
# Requirements:
#   - bash (>= 4.4)
#   - python3 (>= 3.6)
#   - coreutils (basename, cat, chmod, chown, cut, date, df, install,
#     mktemp, mv, od, rm, sha256sum, sort, stat, tail, tr)
#   - sqlite3, gpg, gpgconf, tar, gzip, flock, hostname
#   - findutils (find), gawk/mawk (awk)
#   - curl (optional, required if SEND_TELEGRAM=1)
#   - openssh-client (optional, required if TRANSFER_ENABLED=1)
#   - shred (optional, falls back to rm)
#
# Infrastructure Paths:
#   - Database:           /etc/x-ui/x-ui.db               (root:root 0600)
#   - Master Config:      /etc/x-ui/.env                  (root:root 0600)
#   - Transfer Config:    /etc/x-ui/backup-transfer.env   (root:root 0600, optional)
#   - SSH Private Key:    /etc/x-ui/id_ed25519_backup     (root:root 0600, optional)
#   - SSH Known Hosts:    /etc/x-ui/known_hosts_backup    (root:root 0644/0600, optional)
#   - Backup Store:       /backup/x-ui                    (root:root 0700)
#   - Physical Workdir:   /backup/x-ui/.work              (root:root 0700)
#   - Log File:           /var/log/xui-backup.log         (root:root 0600)
#   - Lock File:          /run/xui-backup/lock            (root:root 0600)
#   - Systemd Service:    /etc/systemd/system/xui-backup.service
#   - Systemd Timer:      /etc/systemd/system/xui-backup.timer
#   - Logrotate Config:   /etc/logrotate.d/xui-backup
#
# Exit Codes:
#   0   - Success, already running, or non-blocking offsite failure
#   1   - Configuration, validation, backup, verification, or runtime failure
#   127 - Required executable was not found
#   130 - Interrupted by SIGINT
#   143 - Terminated by SIGTERM
# ==============================================================================

set -Eeuo pipefail
umask 077

# ==============================================================================
# CONSTANTS & CONFIGURATION
# ==============================================================================

readonly SCRIPT_VERSION="2.10"
readonly ENV_FILE="/etc/x-ui/.env"
readonly TRANSFER_ENV_FILE="/etc/x-ui/backup-transfer.env"
readonly BACKUP_DIR="/backup/x-ui"
readonly DB_PATH="/etc/x-ui/x-ui.db"
readonly LOG_FILE="/var/log/xui-backup.log"
readonly LOCK_DIR="/run/xui-backup"
readonly LOCK_FILE="${LOCK_DIR}/lock"
readonly WORK_BASE="${BACKUP_DIR}/.work"

readonly MAX_AGE_DAYS=14
readonly KEEP_MIN_ARCHIVES=3
readonly MAX_SIZE_GB=2
readonly MIN_PASSPHRASE_CHARS=32
readonly STALE_WORK_HOURS=6
readonly BOOTSTRAP_COMMANDS=(
  date hostname
)

readonly REQUIRED_COMMANDS=(
  awk basename cat chmod chown cut date df find flock gpg gpgconf
  gzip hostname install mktemp mv od python3 rm sha256sum sort sqlite3
  stat tail tar tr
)

for bootstrap_cmd in "${BOOTSTRAP_COMMANDS[@]}"; do
  command -v "$bootstrap_cmd" >/dev/null 2>&1 || {
    printf 'Required bootstrap command not found: %s\n' "$bootstrap_cmd" >&2
    exit 127
  }
done

# ==============================================================================
# GLOBAL STATE
# ==============================================================================

HOST_LABEL="$(hostname -f 2>/dev/null || hostname)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID=""
TEMP_DIR=""
PART_FILE=""
PART_HASH_FILE=""
FINAL_FILE=""
FINAL_HASH_FILE=""

# Telegram settings (loaded from ENV_FILE)
SEND_TELEGRAM=0
TG_BOT_TOKEN=""
TG_CHAT_ID=""
TG_PROXY_URL=""
TG_PROXY_ARGS=()
BACKUP_PASSPHRASE=""
EXPORT_JSON=1

# Off-site transfer settings (loaded from TRANSFER_ENV_FILE)
TRANSFER_ENABLED=0
TRANSFER_HOST=""
TRANSFER_USER=""
TRANSFER_PORT="22"
TRANSFER_KEY=""
TRANSFER_KNOWN_HOSTS=""

# CLI Flags (Defaults)
NO_PRUNE=0
DRY_RUN=0
VERBOSE=0

# ==============================================================================
# LOGGING & CLEANUP
# ==============================================================================

log() {
  local level="$1"
  local message="$2"
  local timestamp
  local line

  [[ "$level" == DEBUG && ${VERBOSE:-0} -ne 1 ]] && return 0

  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  line="$(printf '%s [%s] [%s pid=%s] %s' \
    "$timestamp" "$level" "$(basename -- "$0")" "$$" "$message")"

  if [[ -n "${LOG_FILE:-}" ]]; then
    printf '%s\n' "$line" >> "$LOG_FILE"
  fi

  case "$level" in
    ERROR|WARN)
      printf '%s\n' "$line" >&2
      ;;
    INFO|DEBUG)
      printf '%s\n' "$line"
      ;;
    *)
      printf '%s\n' "$line" >&2
      ;;
  esac
}

prepare_log_file() {
  if [[ -e "$LOG_FILE" && -L "$LOG_FILE" ]]; then
    printf 'Refusing symlink log file: %s\n' "$LOG_FILE" >&2
    exit 1
  fi

  if [[ ! -e "$LOG_FILE" ]]; then
    install -m 0600 -o root -g root /dev/null "$LOG_FILE"
  else
    chown root:root "$LOG_FILE"
    chmod 0600 "$LOG_FILE"
  fi

  [[ "$(stat -c '%U:%G:%a' "$LOG_FILE")" == 'root:root:600' ]] || {
    printf 'Unsafe log file owner/mode: %s\n' "$LOG_FILE" >&2
    exit 1
  }
}

wipe_file() {
  local target_file="$1"
  [[ -f "$target_file" ]] || return 0

  if command -v shred >/dev/null 2>&1; then
    shred -u -z -n 1 -- "$target_file" 2>/dev/null || rm -f -- "$target_file"
  else
    rm -f -- "$target_file"
  fi
}

reap_stale_work_dirs() {
  local hours="${STALE_WORK_HOURS:-24}"
  local stale_min=$(( hours * 60 ))
  local stale
  local list_file

  [[ -d "$WORK_BASE" ]] || return 0

  # 1. Remove orphaned .part files from $BACKUP_DIR with explicit find error handling.
  list_file="$(mktemp "$TEMP_DIR/stale-parts.XXXXXX")"
  if ! find "$BACKUP_DIR" -maxdepth 1 -type f \( -name '*.tar.gz.gpg.part' -o -name '*.tar.gz.gpg.part.sha256' \) -mmin "+${stale_min}" -print0 >"$list_file"; then
    log WARN "Unable to enumerate stale part files in $BACKUP_DIR"
  else
    while IFS= read -r -d '' stale; do
      [[ -f "$stale" ]] || continue
      if [[ "$(stat -c '%U:%G' -- "$stale")" == "root:root" ]]; then
        log WARN "Reaping orphaned part file from a previous crash: $(basename -- "$stale")"
        rm -f -- "$stale"
      fi
    done <"$list_file"
  fi
  rm -f -- "$list_file"

  # 2. Remove dangling sidecar files without matching archives after a crash between mv operations.
  list_file="$(mktemp "$TEMP_DIR/stale-orphans.XXXXXX")"
  if ! find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz.gpg.sha256' -mmin "+${stale_min}" -print0 >"$list_file"; then
    log WARN "Unable to enumerate stale sidecar files in $BACKUP_DIR"
  else
    while IFS= read -r -d '' stale; do
      [[ -f "$stale" ]] || continue
      local parent_archive="${stale%.sha256}"
      if [[ ! -f "$parent_archive" && "$(stat -c '%U:%G' -- "$stale")" == "root:root" ]]; then
        log WARN "Reaping dangling sidecar without archive: $(basename -- "$stale")"
        rm -f -- "$stale"
      fi
    done <"$list_file"
  fi
  rm -f -- "$list_file"

  # 3. Remove stale work.* directories left by previous runs.
  list_file="$(mktemp "$TEMP_DIR/stale-list.XXXXXX")"

  if ! find "$WORK_BASE" -maxdepth 1 -mindepth 1 \
    -type d -name 'work.*' -mmin "+${stale_min}" -print0 >"$list_file"; then
    log WARN "Unable to enumerate stale work directories in $WORK_BASE"
    rm -f -- "$list_file"
    return 0
  fi

  while IFS= read -r -d '' stale; do
    [[ -z "$stale" || "$stale" == "/" || "$stale" == "$WORK_BASE" ]] && continue
    [[ "$stale" == "$TEMP_DIR" ]] && continue

    [[ "$(stat -c '%U:%G' -- "$stale")" == "root:root" ]] || {
      log ERROR "Refusing to remove stale work dir with unsafe owner: $stale"
      continue
    }
    gpgconf --homedir "$stale/gnupg" --kill gpg-agent 2>/dev/null || true
    log WARN "Reaping stale work dir from a previous run: $(basename -- "$stale")"
    wipe_file "$stale/passphrase"
    wipe_file "$stale/tgtok"
    rm -rf -- "$stale"
  done <"$list_file"

  rm -f -- "$list_file"
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  local leftover

  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    wipe_file "$TEMP_DIR/passphrase"
    wipe_file "$TEMP_DIR/tgtok"

    for leftover in "$TEMP_DIR"/env.* "$TEMP_DIR"/curl.*; do
      [[ -f "$leftover" ]] && wipe_file "$leftover"
    done
    if [[ -n "${GNUPGHOME:-}" && -d "$GNUPGHOME" ]]; then
      gpgconf --homedir "$GNUPGHOME" --kill gpg-agent 2>/dev/null || true
    fi
    rm -rf -- "$TEMP_DIR"
  fi

  # Roll back the sidecar file if the script fails before moving the main archive.
  if [[ -n "${FINAL_HASH_FILE:-}" && -f "$FINAL_HASH_FILE" && -n "${FINAL_FILE:-}" && ! -f "$FINAL_FILE" ]]; then
    rm -f -- "$FINAL_HASH_FILE"
  fi

  [[ -n "${PART_HASH_FILE:-}" ]] && rm -f -- "$PART_HASH_FILE"
  [[ -n "${PART_FILE:-}" ]] && rm -f -- "$PART_FILE"

  unset BACKUP_PASSPHRASE TG_BOT_TOKEN TRANSFER_KEY
  exit "$rc"
}

on_error() {
  local rc="$1"
  local line="$2"

  trap - ERR
  log ERROR "Failed at line $line; exit=$rc"

  send_tg text "3x-ui backup FAILED
Host: $HOST_LABEL
UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Line: $line
Exit: $rc" || true

  exit "$rc"
}

# ==============================================================================
# HELPER & PARSING FUNCTIONS
# ==============================================================================

make_run_id() {
  local nonce
  nonce="$(od -An -N4 -tu4 /dev/urandom | tr -d '[:space:]')"
  [[ "$nonce" =~ ^[0-9]+$ ]] || nonce="${RANDOM}${RANDOM}"
  RUN_ID="${TIMESTAMP}-$$-${nonce}"
}

newest_archive() {
  find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz.gpg' | sort | tail -n 1
}

oldest_archive() {
  find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz.gpg' | sort | head -n 1
}

archive_set_size_bytes() {
  find "$BACKUP_DIR" -maxdepth 1 -type f \( -name '*.tar.gz.gpg' -o -name '*.tar.gz.gpg.sha256' \) -printf '%s\n' \
    | awk '{sum+=$1} END {print sum+0}'
}

oldest_archives_sorted() {
  find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz.gpg' | sort
}

check_disk_space() {
  local target_dir="$1"
  local required_mb="$2"
  local avail_kb

  avail_kb="$(df -kP "$target_dir" 2>/dev/null | awk 'NR==2 {print $4}')"
  [[ "$avail_kb" =~ ^[0-9]+$ ]] || { log ERROR "Unable to determine disk space on $target_dir"; exit 1; }
  if (( avail_kb < required_mb * 1024 )); then
    log ERROR "Insufficient disk space on $target_dir: ${avail_kb}KB available, ${required_mb}MB required"
    exit 1
  fi
}

required_work_mb() {
  local db_bytes db_mb factor
  db_bytes="$(stat -c %s "$DB_PATH" 2>/dev/null || echo 0)"
  factor=4
  [[ "${EXPORT_JSON:-1}" == 1 ]] && factor=6
  db_mb=$(( (db_bytes * factor) / 1024 / 1024 ))
  (( db_mb < 100 )) && db_mb=100
  printf '%s' "$db_mb"
}

load_kv_file() {
  local file="$1"
  local allowed_csv="$2"
  local env_dump item key value

  [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]] || return 1

  env_dump="$(mktemp "$TEMP_DIR/env.XXXXXX")"
  chmod 600 "$env_dump"

  if ! python3 - "$file" "$allowed_csv" >"$env_dump" <<'PY'
import ast
import re
import sys

path, allowed_raw = sys.argv[1:]
allowed = set(allowed_raw.split(','))
rx = re.compile(r'^([A-Z][A-Z0-9_]*)=(.*)$')

with open(path, encoding='utf-8') as f:
    for n, raw in enumerate(f, 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        m = rx.fullmatch(line)
        if not m or m.group(1) not in allowed:
            raise SystemExit(f'Invalid or forbidden entry at line {n}')
        key, val = m.groups()
        if val[:1] in ("'", '"'):
            try:
                val = ast.literal_eval(val)
            except (SyntaxError, ValueError) as e:
                raise SystemExit(f'Invalid quoted value at line {n}: {e}')
            if not isinstance(val, str):
                raise SystemExit(f'Value at line {n} must be a string')
        elif val != val.strip() or any(c in val for c in '`$\\'):
            raise SystemExit(f'Unsafe unquoted value at line {n}; quote it')
        if '\x00' in val or '\n' in val or '\r' in val:
            raise SystemExit(f'Invalid control character at line {n}')
        print(key + '=' + val)
PY
  then
    wipe_file "$env_dump"
    return 1
  fi

  while IFS= read -r item || [[ -n "$item" ]]; do
    key="${item%%=*}"
    value="${item#*=}"
    printf -v "$key" '%s' "$value"
  done <"$env_dump"

  wipe_file "$env_dump"
}

# ==============================================================================
# CONFIGURATION LOADERS & VALIDATION
# ==============================================================================

load_env() {
  load_kv_file "$ENV_FILE" 'BACKUP_PASSPHRASE,SEND_TELEGRAM,TG_BOT_TOKEN,TG_CHAT_ID,TG_PROXY_URL,EXPORT_JSON'
}

load_transfer_config() {
  [[ -f "$TRANSFER_ENV_FILE" ]] || {
    log WARN 'Offsite delivery disabled: transfer config absent'
    return 0
  }

  [[ "$(stat -c '%U:%G:%a' "$TRANSFER_ENV_FILE")" == root:root:600 ]] || {
    log ERROR 'Offsite delivery disabled: unsafe transfer config owner/mode'
    return 0
  }

  if ! load_kv_file "$TRANSFER_ENV_FILE" \
    'TRANSFER_ENABLED,TRANSFER_HOST,TRANSFER_USER,TRANSFER_PORT,TRANSFER_KEY,TRANSFER_KNOWN_HOSTS'; then
    log ERROR "Offsite delivery disabled: invalid configuration file: $TRANSFER_ENV_FILE"
    TRANSFER_ENABLED=0
    return 0
  fi

  : "${TRANSFER_ENABLED:=0}"
  [[ "$TRANSFER_ENABLED" =~ ^[01]$ ]] || {
    log ERROR 'Offsite delivery disabled: invalid TRANSFER_ENABLED'
    TRANSFER_ENABLED=0
    return 0
  }

  [[ "$TRANSFER_ENABLED" == 1 ]] || return 0

  if [[ ! "$TRANSFER_HOST" =~ ^[A-Za-z0-9.-]+$ || \
        ! "$TRANSFER_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ || \
        ! "$TRANSFER_PORT" =~ ^[1-9][0-9]{0,4}$ || \
        ! -f "$TRANSFER_KEY" || \
        ! -f "$TRANSFER_KNOWN_HOSTS" ]]; then
    log ERROR 'Offsite delivery disabled: invalid transfer endpoint configuration'
    TRANSFER_ENABLED=0
    return 0
  fi

  if (( 10#$TRANSFER_PORT < 1 || 10#$TRANSFER_PORT > 65535 )); then
    log ERROR 'Offsite delivery disabled: TRANSFER_PORT out of range'
    TRANSFER_ENABLED=0
    return 0
  fi

  [[ "$(stat -c '%U:%G:%a' "$TRANSFER_KEY")" == root:root:600 ]] || {
    log ERROR 'Offsite delivery disabled: unsafe private-key owner/mode'
    TRANSFER_ENABLED=0
    return 0
  }

  local kh_stat
  kh_stat="$(stat -c '%U:%G:%a' "$TRANSFER_KNOWN_HOSTS")"
  if [[ "$kh_stat" != "root:root:644" && "$kh_stat" != "root:root:600" ]]; then
    log ERROR 'Offsite delivery disabled: unsafe known_hosts owner/mode'
    TRANSFER_ENABLED=0
    return 0
  fi

  if ! command -v ssh >/dev/null || ! command -v grep >/dev/null; then
    log ERROR 'Offsite delivery disabled: ssh or grep not found'
    TRANSFER_ENABLED=0
    return 0
  fi

  return 0
}

require_cmd() {
  local cmd

  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || {
      log ERROR "Required command not found: $cmd"
      exit 127
    }
  done
}

prepare_backup_tree() {
  [[ -d "$BACKUP_DIR" ]] || install -d -m 0700 -o root -g root "$BACKUP_DIR"

  [[ "$(stat -c '%U:%G:%a' "$BACKUP_DIR")" == "root:root:700" ]] || {
    log ERROR "Unsafe backup directory owner/mode: $BACKUP_DIR"
    exit 1
  }

  install -d -m 0700 -o root -g root "$WORK_BASE"

  [[ "$(stat -c '%U:%G:%a' "$WORK_BASE")" == "root:root:700" ]] || {
    log ERROR "Unsafe work directory owner/mode: $WORK_BASE"
    exit 1
  }
}

validate() {
  [[ $EUID -eq 0 ]] || { log ERROR 'Must run as root'; exit 1; }
  [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]] || { log ERROR 'Internal error: TEMP_DIR not ready'; exit 1; }
  [[ -f "$ENV_FILE" && -f "$DB_PATH" ]] || { log ERROR 'Missing .env or database'; exit 1; }
  [[ "$(stat -c '%U:%G:%a' "$ENV_FILE")" == "root:root:600" ]] || {
    log ERROR "Unsafe .env owner/mode: $ENV_FILE"
    exit 1
  }

  local required_mb
  required_mb="$(required_work_mb)"
  check_disk_space "$BACKUP_DIR" "$required_mb"
  check_disk_space "/" "$required_mb"

  if ! load_env; then
    log ERROR "Invalid configuration file: $ENV_FILE"
    exit 1
  fi

  if [[ -z "${BACKUP_PASSPHRASE:-}" ]]; then
    log ERROR 'BACKUP_PASSPHRASE is required'
    exit 1
  fi

  if (( ${#BACKUP_PASSPHRASE} < MIN_PASSPHRASE_CHARS )); then
    log ERROR "BACKUP_PASSPHRASE must be at least ${MIN_PASSPHRASE_CHARS} characters"
    exit 1
  fi

  : "${SEND_TELEGRAM:=0}"
  [[ "$SEND_TELEGRAM" =~ ^[01]$ ]] || {
    log ERROR 'SEND_TELEGRAM must be 0 or 1'
    exit 1
  }

  : "${EXPORT_JSON:=1}"
  [[ "$EXPORT_JSON" =~ ^[01]$ ]] || {
    log ERROR 'EXPORT_JSON must be 0 or 1'
    exit 1
  }

  if [[ "$SEND_TELEGRAM" == 1 ]]; then
    require_cmd curl

    if [[ -z "${TG_BOT_TOKEN:-}" ]]; then
      log ERROR 'TG_BOT_TOKEN is required when SEND_TELEGRAM=1'
      exit 1
    fi

    if [[ -z "${TG_CHAT_ID:-}" ]]; then
      log ERROR 'TG_CHAT_ID is required when SEND_TELEGRAM=1'
      exit 1
    fi

    [[ "$TG_BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || {
      log ERROR 'Invalid TG_BOT_TOKEN'
      exit 1
    }

    [[ "$TG_CHAT_ID" =~ ^-?[0-9]+$ ]] || {
      log ERROR 'Invalid TG_CHAT_ID'
      exit 1
    }
  fi

  if [[ -n "${TG_PROXY_URL:-}" ]]; then
    [[ "$TG_PROXY_URL" =~ ^(socks5h?|https?)://[^[:space:]]+$ ]] || {
      log ERROR 'Invalid TG_PROXY_URL'
      exit 1
    }

    TG_PROXY_ARGS=(--proxy "$TG_PROXY_URL")
  fi

  load_transfer_config
}

# ==============================================================================
# TELEGRAM INTEGRATION
# ==============================================================================

write_tg_curl_config() {
  local method="$1"
  local cfg="$2"
  local tok="$TEMP_DIR/tgtok"

  printf %s "$TG_BOT_TOKEN" >"$tok"
  chmod 600 "$tok"

  python3 - "$tok" "$method" "$cfg" <<'PY'
from pathlib import Path
import sys

tok_path, method, path = sys.argv[1:]
token = Path(tok_path).read_text(encoding='utf-8')
if any(c in token for c in '\n\r"\\'):
    raise SystemExit('unsafe telegram token')
Path(path).write_text(f'url = "https://api.telegram.org/bot{token}/{method}"\n', encoding='utf-8')
PY

  wipe_file "$tok"
  chmod 600 "$cfg"
}

send_tg() {
  local kind="$1"
  local payload="$2"
  local response cfg caption rc=0

  [[ "$SEND_TELEGRAM" == 1 ]] || return 0
  [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]] || return 1

  if [[ "$kind" != text ]]; then
    local file_bytes
    file_bytes="$(stat -c %s -- "$payload" 2>/dev/null || echo 0)"
    if (( file_bytes > 49 * 1024 * 1024 )); then
      log WARN "Archive size (${file_bytes} bytes) exceeds Telegram 50MB limit; sending text alert"
      send_tg text "⚠️ 3x-ui backup archive exceeds Telegram 50MB limit (${file_bytes} bytes). Document attachment skipped; local and offsite delivery proceed normally." || true
      return 0
    fi
  fi

  response="$(mktemp "$TEMP_DIR/tg.XXXXXX")"
  cfg="$(mktemp "$TEMP_DIR/curl.XXXXXX")"

  if [[ "$kind" == text ]]; then
    write_tg_curl_config sendMessage "$cfg"
    curl --config "$cfg" \
      --fail --silent --show-error \
      --connect-timeout 10 --max-time 45 \
      --retry 3 --retry-delay 3 --retry-connrefused \
      "${TG_PROXY_ARGS[@]}" \
      -X POST \
      --data-urlencode "chat_id=$TG_CHAT_ID" \
      --data-urlencode "text=$payload" \
      -o "$response" || rc=$?
  else
    write_tg_curl_config sendDocument "$cfg"
    caption="3x-ui backup | ${HOST_LABEL} | ${TIMESTAMP}"
    curl --config "$cfg" \
      --fail --silent --show-error \
      --connect-timeout 10 --max-time 300 \
      --retry 3 --retry-delay 5 --retry-connrefused \
      "${TG_PROXY_ARGS[@]}" \
      -X POST \
      -F "chat_id=$TG_CHAT_ID" \
      -F "caption=$caption" \
      -F "document=@$payload" \
      -o "$response" || rc=$?
  fi

  wipe_file "$cfg"

  if (( rc == 0 )); then
    python3 - "$response" <<'PY'
import json
import sys

with open(sys.argv[1], encoding='utf-8') as f:
    response = json.load(f)
raise SystemExit(0 if response.get('ok') is True else 1)
PY
    rc=$?
  fi

  rm -f -- "$response"
  return "$rc"
}

# ==============================================================================
# BACKUP & EXPORT CORE
# ==============================================================================

backup_sqlite() {
  local out="$1"
  local out_escaped="${out//\'/\'\'}"
  sqlite3 "$DB_PATH" <<SQL
.timeout 8000
.backup '${out_escaped}'
SQL
  [[ -s "$out" && "$(sqlite3 "$out" 'PRAGMA integrity_check;')" == ok ]]
}

export_payload() {
  local db="$1"
  local json="$2"
  local manifest="$3"
  local export_json="$4"

  python3 - "$db" "$json" "$manifest" "$HOST_LABEL" "$TIMESTAMP" "$SCRIPT_VERSION" "$export_json" <<'PY'
import base64
import hashlib
import json
import sqlite3
import sys

p_db, p_json, p_manifest, host, created, version, export_json_flag = sys.argv[1:8]
export_json = export_json_flag == "1"

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def json_default(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {
            "__xui_type__": "blob",
            "base64": base64.b64encode(bytes(value)).decode("ascii"),
        }
    return str(value)

conn = sqlite3.connect(p_db)
conn.row_factory = sqlite3.Row
schema = conn.execute(
    "SELECT name, sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
).fetchall()

if not schema:
    raise SystemExit('No application tables found; refusing JSON export')

counts = {}
ddl = {}

if export_json:
    with open(p_json, 'w', encoding='utf-8') as out:
        out.write('{"format":"xui-json-export-v2","created_at_utc":')
        json.dump(created, out, ensure_ascii=False)
        out.write(',"hostname":')
        json.dump(host, out, ensure_ascii=False)
        out.write(',"tables":{')
        first_table = True
        for entry in schema:
            name = entry['name']
            quoted = '"' + name.replace('"', '""') + '"'
            if not first_table:
                out.write(',')
            first_table = False
            json.dump(name, out, ensure_ascii=False)
            out.write(':[')
            count = 0
            first_row = True
            for row in conn.execute('SELECT * FROM ' + quoted):
                if not first_row:
                    out.write(',')
                first_row = False
                json.dump(
                    dict(row),
                    out,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(',', ':'),
                    default=json_default
                )
                count += 1
            out.write(']')
            counts[name] = count
            ddl[name] = entry['sql']
        out.write('}}')
else:
    for entry in schema:
        name = entry['name']
        quoted = '"' + name.replace('"', '""') + '"'
        count = conn.execute('SELECT COUNT(*) FROM ' + quoted).fetchone()[0]
        counts[name] = count
        ddl[name] = entry['sql']

manifest = {
    "format": "xui-backup-manifest-v2",
    "created_at_utc": created,
    "hostname": host,
    "script_version": version,
    "sqlite_version": sqlite3.sqlite_version,
    "database_file": "x-ui.db",
    "database_sha256": digest(p_db),
    "tables": [x['name'] for x in schema],
    "row_counts": counts,
    "schema_ddl": ddl,
    "json_export": export_json,
}

if export_json:
    manifest["json_file"] = "3xui_export.json"
    manifest["json_sha256"] = digest(p_json)

with open(p_manifest, 'w', encoding='utf-8') as f:
    json.dump(manifest, f, ensure_ascii=False, sort_keys=True, indent=2)

conn.close()
PY
}

# ==============================================================================
# VERIFICATION & ROTATION
# ==============================================================================

# Verify a published archive end-to-end:
# SHA-256 sidecar, GPG decryption, tar extraction, manifest hashes,
# JSON export consistency, and SQLite integrity.
verify_archive() {
  local latest="$1"
  local hash 
  local test_dir 
  local payload 
  local table_count 
  local hash_basename

  [[ -f "$latest" ]] || {
    log ERROR "verification failed: archive does not exist: $latest"
    return 1
  }

  hash="${latest}.sha256"
  hash_basename="$(basename -- "$hash")"

  if ! (cd "$BACKUP_DIR" && sha256sum -c --status -- "$hash_basename"); then
    log ERROR "verification failed: sha256 mismatch or missing sidecar for $(basename -- "$latest")"
    return 1
  fi

  test_dir="$(mktemp -d "$TEMP_DIR/verify.XXXXXX")" || {
    log ERROR "archive verification failed: cannot create temporary verification directory"
    return 1
  }
  payload="$test_dir/payload.tar.gz"

  if ! gpg --batch --yes --pinentry-mode loopback --no-symkey-cache \
    --passphrase-file "$TEMP_DIR/passphrase" \
    --output "$payload" \
    --decrypt "$latest"; then
    log ERROR "verification failed: gpg decrypt failed for $(basename -- "$latest")"
    rm -rf -- "$test_dir"
    return 1
  fi

  # --- NEW: validate archive composition before extraction (consistency with restore)
  local members
  if ! members="$(tar -tzf "$payload" | LC_ALL=C sort)"; then
    log ERROR "verification failed: cannot list archive members for $(basename -- "$latest")"
    rm -rf -- "$test_dir"
    return 1
  fi

  case "$members" in
    $'manifest.json
x-ui.db'|$'3xui_export.json
manifest.json
x-ui.db')
      ;;
    *)
      log ERROR "verification failed: invalid archive composition for $(basename -- "$latest")"
      rm -rf -- "$test_dir"
      return 1
      ;;
  esac
  # --- END NEW

  if ! tar -xzf "$payload" -C "$test_dir" --no-same-owner --no-same-permissions; then
    log ERROR "verification failed: tar extract failed for $(basename -- "$latest")"
    rm -rf -- "$test_dir"
    return 1
  fi

  if ! python3 - "$test_dir/manifest.json" "$test_dir/x-ui.db" "$test_dir/3xui_export.json" <<'PY'
import hashlib
import json
import os
import sys

p_manifest, p_db, p_json = sys.argv[1:4]
m = json.load(open(p_manifest, encoding='utf-8'))

def h(p):
    x = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1048576), b''):
            x.update(b)
    return x.hexdigest()

if m.get('format') != 'xui-backup-manifest-v2':
    raise SystemExit('invalid manifest format')

if h(p_db) != m.get('database_sha256'):
    raise SystemExit('database SHA-256 mismatch')

json_export = m.get('json_export', True)
if json_export:
    if not os.path.isfile(p_json):
        raise SystemExit('json_export=true in manifest, but export file missing')
    if 'json_sha256' not in m:
        raise SystemExit('json_export=true but manifest has no json_sha256')
    if h(p_json) != m['json_sha256']:
        raise SystemExit('JSON export SHA-256 mismatch')
else:
    if os.path.isfile(p_json):
        raise SystemExit('json_export=false in manifest, but export file present')

if not m.get('tables'):
    raise SystemExit('manifest has no tables listed')
PY
  then
    log ERROR "archive verification failed: manifest/hash validation failed for $(basename -- "$latest")"
    rm -rf -- "$test_dir"
    return 1
  fi

  if [[ "$(sqlite3 "$test_dir/x-ui.db" 'PRAGMA integrity_check;')" != ok ]]; then
    log ERROR "verification failed: sqlite integrity_check failed"
    rm -rf -- "$test_dir"
    return 1
  fi

  table_count="$(sqlite3 "$test_dir/x-ui.db" \
    "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%';")" || {
      rm -rf -- "$test_dir"
      return 1
    }

  rm -rf -- "$test_dir"
  log INFO "archive_verification_ok; archive=$(basename -- "$latest"); application_tables=$table_count"
  return 0
}

 weekly_test() {
  local oldest
 
   # Run only on Mondays; ISO weekday: Monday = 1.
   [[ "$(date -u +%u)" == "1" ]] || return 0
 
  if ! oldest="$(oldest_archive)"; then
    log ERROR "weekly restore test: unable to locate the oldest archive"
     return 1
   fi
 
  if [[ -z "$oldest" ]]; then
     log WARN "weekly restore test skipped: no archive found"
     return 0
   fi
 
  if ! verify_archive "$oldest"; then
    log ERROR "weekly restore test failed: $(basename -- "$oldest")"
     return 1
   fi
 
  log INFO "weekly_restore_test_ok; archive=$(basename -- "$oldest") (oldest retained copy)"
   return 0
 }

rotate() {
  local max size old old_size side_size
  local -a archives=()
  local archive_list
  local -a age_candidates=()

  archive_list="$(oldest_archives_sorted)" || {
    log ERROR "Unable to enumerate archives in $BACKUP_DIR"
    return 1
  }

  if [[ -n "$archive_list" ]]; then
    mapfile -t age_candidates <<< "$archive_list"
  fi

  local total_count=${#age_candidates[@]}
  local deletable=$(( total_count - KEEP_MIN_ARCHIVES ))
  if (( deletable > 0 )); then
    local age_idx candidate mtime now age_seconds
    now="$(date +%s)"

    for (( age_idx=0; age_idx<deletable; age_idx++ )); do
      candidate="${age_candidates[$age_idx]}"
      [[ -f "$candidate" ]] || continue
      mtime="$(stat -c %Y -- "$candidate")" || return 1
      age_seconds=$(( now - mtime ))

      if (( age_seconds > MAX_AGE_DAYS * 86400 )); then
        if (( DRY_RUN || NO_PRUNE )); then
          log INFO "[$([ "$DRY_RUN" -eq 1 ] && echo dry-run || echo no-prune)] skip age delete: $(basename -- "$candidate")"
        else
          rm -f -- "$candidate" "${candidate}.sha256"
          log WARN "Rotated by age: $(basename -- "$candidate")"
        fi
      fi
    done
  fi

  max=$(( MAX_SIZE_GB * 1024 * 1024 * 1024 ))
  size="$(archive_set_size_bytes)"
  [[ "$size" =~ ^[0-9]+$ ]] || { log ERROR "Unable to compute archive set size"; return 1; }

  archive_list="$(oldest_archives_sorted)" || {
    log ERROR "Unable to enumerate archives in $BACKUP_DIR"
    return 1
  }

  if [[ -n "$archive_list" ]]; then
    mapfile -t archives <<< "$archive_list"
  fi

  local total_archives=${#archives[@]}
  for old in "${archives[@]}"; do
    (( size <= max )) && break
    (( total_archives <= KEEP_MIN_ARCHIVES )) && break

    [[ -f "$old" ]] || continue
    old_size="$(stat -c %s -- "$old")" || return 1
    side_size=0
    if [[ -f "${old}.sha256" ]]; then
      side_size="$(stat -c %s -- "${old}.sha256")" || return 1
    fi

    if (( DRY_RUN || NO_PRUNE )); then
      log INFO "[$([ "$DRY_RUN" -eq 1 ] && echo dry-run || echo no-prune)] skip size delete: $(basename -- "$old"); bytes=$(( old_size + side_size ))"
    else
      rm -f -- "$old" "${old}.sha256"
      log WARN "Rotated by size: $(basename -- "$old"); bytes=$(( old_size + side_size ))"
    fi

    if (( ! NO_PRUNE || DRY_RUN )); then
      size=$(( size - old_size - side_size ))
      (( total_archives-- ))
    fi
  done

  if (( DRY_RUN )); then
    log INFO "[dry-run] Predicted archive-set size after rotation: ${size} bytes"
  elif (( NO_PRUNE )); then
    if (( size > max )); then
      log WARN "no-prune: archive set (${size} bytes) exceeds MAX_SIZE_GB (${MAX_SIZE_GB}GB); pruning skipped by flag"
      send_tg text "3x-ui backup: WARNING
Host: $HOST_LABEL
Archive set size (${size} bytes) exceeds ${MAX_SIZE_GB}GB, but --no-prune is active.
No deletion performed. Manual review recommended." || true
    fi
  elif (( size > max && total_archives <= KEEP_MIN_ARCHIVES )); then
    log WARN "Size limit exceeded, but KEEP_MIN_ARCHIVES reached. Halting deletion."
    send_tg text "3x-ui backup: WARNING
Host: $HOST_LABEL
Size limit (${MAX_SIZE_GB}GB) exceeded but KEEP_MIN_ARCHIVES=${KEEP_MIN_ARCHIVES} reached.
Manual attention needed (increase MAX_SIZE_GB or free disk space)." || true
  fi
}

# ==============================================================================
# OFFSITE DELIVERY
# ==============================================================================

deliver_offsite() {
  local archive="$1"
  local hash="$2"
  local size="$3"
  local name output rc

  [[ "$TRANSFER_ENABLED" == 1 ]] || return 0

  name="$(basename -- "$archive")"
  output="$(mktemp "$TEMP_DIR/offsite.XXXXXX")"

  set +e
  ssh -i "$TRANSFER_KEY" -p "$TRANSFER_PORT" \
    -o BatchMode=yes \
    -o IdentitiesOnly=yes \
    -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$TRANSFER_KNOWN_HOSTS" \
    -o GlobalKnownHostsFile=/dev/null \
    -o ConnectTimeout=15 \
    -o ConnectionAttempts=2 \
    -o ServerAliveInterval=15 \
    -o ServerAliveCountMax=3 \
    -o LogLevel=ERROR \
    "${TRANSFER_USER}@${TRANSFER_HOST}" \
    "receive ${name} ${hash} ${size}" \
    <"$archive" >"$output" 2>&1
  rc=$?
  set -e

  if (( rc == 0 )) && grep -qx "OK ${name} ${hash} ${size}" "$output"; then
    log INFO "offsite_delivery_ok; archive=$name; bytes=$size; sha256=$hash"
    rm -f -- "$output"
    return 0
  fi

  log ERROR "offsite_delivery_failed; archive=$name; exit=$rc; diagnostic=$(tr '\n' ' ' <"$output" | tr -cd '[:print:]' | cut -c1-300)"
  rm -f -- "$output"
  return 1
}

# ==============================================================================
# MAIN ROUTINE
# ==============================================================================

main() {
  [[ $EUID -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }
  prepare_log_file
  require_cmd "${REQUIRED_COMMANDS[@]}"

  trap cleanup EXIT
  trap 'on_error $? $LINENO' ERR
  trap 'log WARN "Received SIGINT"; exit 130' INT
  trap 'log WARN "Received SIGTERM"; exit 143' TERM

  install -d -m 0700 -o root -g root "$LOCK_DIR"
  exec 9>"$LOCK_FILE"
  flock -n 9 || { log INFO 'Already running'; exit 0; }

  prepare_backup_tree
  check_disk_space "$WORK_BASE" "$(required_work_mb)"

  TEMP_DIR="$(mktemp -d "$WORK_BASE/work.XXXXXX")"
  chmod 700 "$TEMP_DIR"

  make_run_id
  validate

  if (( DRY_RUN )); then
    log INFO "[dry-run] validation ok; no backup, upload, pruning, or stale-artifact cleanup will be performed"
    rotate || {
      log ERROR "[dry-run] rotation simulation failed"
      return 1
    }
    return 0
  fi

  reap_stale_work_dirs

  export GNUPGHOME="$TEMP_DIR/gnupg"
  install -d -m 0700 -o root -g root "$GNUPGHOME"

  printf %s "$BACKUP_PASSPHRASE" >"$TEMP_DIR/passphrase"
  chmod 600 "$TEMP_DIR/passphrase"
  unset BACKUP_PASSPHRASE

  local db json manifest tarfile gzipfile part final hpart hfinal hash size

  db="$TEMP_DIR/x-ui.db"
  json="$TEMP_DIR/3xui_export.json"
  manifest="$TEMP_DIR/manifest.json"
  tarfile="$TEMP_DIR/payload.tar"
  gzipfile="$TEMP_DIR/payload.tar.gz"
  part="$BACKUP_DIR/xui-backup-$RUN_ID.tar.gz.gpg.part"
  final="$BACKUP_DIR/xui-backup-$RUN_ID.tar.gz.gpg"
  hpart="${part}.sha256"
  hfinal="${final}.sha256"
  FINAL_FILE="$final"
  FINAL_HASH_FILE="$hfinal"
  PART_FILE="$part"
  PART_HASH_FILE="$hpart"

  log INFO "Backup started; version=$SCRIPT_VERSION"

  backup_sqlite "$db"
  export_payload "$db" "$json" "$manifest" "$EXPORT_JSON"

  local -a tar_members=(x-ui.db manifest.json)
  [[ "$EXPORT_JSON" == 1 ]] && tar_members+=(3xui_export.json)
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    -cf "$tarfile" -C "$TEMP_DIR" "${tar_members[@]}"

  gzip -n -6 -c "$tarfile" >"$gzipfile"

  # NOTE: s2k-count=65011712 (the maximum value defined by the OpenPGP spec) - a
  # hardened key-derivation function that adds a noticeable delay (several seconds)
  # to encryption/decryption. Make sure the systemd unit / cron job does not set
  # TimeoutStartSec (or an equivalent timeout) shorter than that.
  gpg --batch --yes --pinentry-mode loopback --no-symkey-cache --symmetric \
    --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65011712 \
    --compress-algo none --passphrase-file "$TEMP_DIR/passphrase" \
    --output "$part" "$gzipfile"

  hash="$(sha256sum -- "$part" | awk '{print $1}')"
  if [[ ! "$hash" =~ ^[[:xdigit:]]{64}$ ]]; then
    log ERROR "Failed to calculate a valid SHA-256 for: $part"
    exit 1
  fi

  printf '%s  %s\n' "$hash" "$(basename "$final")" >"$hpart"
  chmod 600 "$part" "$hpart"
  mv -f -- "$hpart" "$hfinal"
  PART_HASH_FILE=""
  mv -f -- "$part" "$final"
  PART_FILE=""
  FINAL_FILE=""
  FINAL_HASH_FILE=""

  if ! verify_archive "$final"; then
    log ERROR "New archive failed restore verification; keeping it for investigation and stopping"
    send_tg text "3x-ui backup FAILED verification
Host: $HOST_LABEL
UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Archive: $(basename -- "$final")
Local archive was created but failed restore verification." || true
    return 1
  fi

  size="$(stat -c %s -- "$final")"

  if [[ "$TRANSFER_ENABLED" == 1 ]]; then
    if ! deliver_offsite "$final" "$hash" "$size"; then
      log ERROR "Offsite delivery FAILED; archive=$(basename -- "$final")"
      send_tg text "3x-ui OFFSITE delivery FAILED
Host: $HOST_LABEL
UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Archive: $(basename -- "$final")
Destination: ${TRANSFER_HOST:-remote_storage}
Local backup: OK
See /var/log/xui-backup.log for diagnostic." || true
    fi
  fi

  rotate || log WARN "rotation failed; local archive kept"

  weekly_test || log WARN "weekly restore test failed; local archive kept"


  log INFO "Local backup completed; archive=$(basename "$final"); sha256=$hash"

  if [[ "$SEND_TELEGRAM" == 1 ]]; then
    send_tg file "$final" || log WARN "Archive created, but Telegram document upload failed"
  fi

  send_tg text "3x-ui backup OK
Host: $HOST_LABEL
UTC: $TIMESTAMP
Archive: $(basename "$final")
SHA-256: $hash" || true
  return 0
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [--dry-run] [--no-prune] [--verbose] [--help]
  --dry-run   Validate config and simulate rotate(); do not create or send a backup
  --no-prune  Create and deliver a backup, but skip deletion in rotate()
  --verbose   Enable DEBUG-level log output
  --help      Show this message
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-prune) NO_PRUNE=1; shift ;;
      --dry-run)  DRY_RUN=1; shift ;;
      -v|--verbose) VERBOSE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Error: Unknown argument '$1'" >&2; usage >&2; exit 1 ;;
    esac
  done
}

parse_args "$@"
main "$@"