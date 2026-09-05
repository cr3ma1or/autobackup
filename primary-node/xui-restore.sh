#!/usr/bin/env bash
# ==============================================================================
# Script: xui-restore
# Version: v2.4; compatible with xui-backup v2.1-v2.10 archives
# Description: Restores a verified 3x-ui backup archive, validates manifest
# metadata and schema before confirmation, and preserves a rollback copy of
# the current database.
# Context / Constraints: Must be run as root; requires secure permissions on
#                        the environment file and backup directory.
# Inputs: Optional archive filename; /etc/x-ui/.env; encrypted backup archive.
# Outputs: Restored x-ui database, service status messages, rollback database.
# Dependencies: bash, python3, sqlite3, gpg, tar, sha256sum, systemctl.
# Exit Codes: 0 on success or cancellation; non-zero on validation, verification,
#             decryption, restore, or service-start failure.
# ==============================================================================

set -Eeuo pipefail
umask 077

# ------------------------------------------------------------------------------
# 1. Configuration & Constants
# ------------------------------------------------------------------------------

readonly ENV_FILE=/etc/x-ui/.env
readonly BACKUP_DIR=/backup/x-ui
readonly DB_PATH=/etc/x-ui/x-ui.db
readonly DB_DIR=${DB_PATH%/*}
readonly XUI_SERVICE=x-ui
readonly LOCK_DIR=/run/xui-backup
readonly LOCK_FILE="${LOCK_DIR}/lock"

TEMP_DIR=""
ROLLBACK_DB=""
SERVICE_STOPPED=0
REPLACED_DB=0
ARCHIVE=""
HASH_FILE=""
LOCK_FD=-1

# ------------------------------------------------------------------------------
# 2. Helper Functions & Error Handling
# ------------------------------------------------------------------------------

# Loads approved environment variables from the protected .env file.
load_env() {
  local item key value env_dump

  env_dump="$(mktemp "${BACKUP_DIR}/.restore_env.XXXXXX")"
  chmod 600 "$env_dump"

  if ! python3 - "$ENV_FILE" >"$env_dump" <<'PY'
import ast, re, sys
allowed = {"BACKUP_PASSPHRASE"}
line_re = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
with open(sys.argv[1], encoding="utf-8") as f:
    for n, raw in enumerate(f, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = line_re.fullmatch(line)
        if not m or m.group(1) not in allowed:
            raise SystemExit(f"Invalid or forbidden .env entry at line {n}")
        key, val = m.groups()
        if val[:1] in ("'", '"'):
            try:
                val = ast.literal_eval(val)
            except (SyntaxError, ValueError) as e:
                raise SystemExit(f"Invalid quoted value at line {n}: {e}")
            if not isinstance(val, str):
                raise SystemExit(f"Value at line {n} must be a string")
        elif val != val.strip() or any(c in val for c in "`$\\"):
            raise SystemExit(f"Unsafe unquoted value at line {n}; quote it")
        if "\x00" in val or "\n" in val or "\r" in val:
            raise SystemExit(f"Invalid control character at line {n}")
        print(key + "=" + val)
PY
  then
    rm -f -- "$env_dump"
    return 1
  fi

  while IFS= read -r item || [[ -n "$item" ]]; do
    key=${item%%=*}
    value=${item#*=}
    printf -v "$key" '%s' "$value"
  done <"$env_dump"

  rm -f -- "$env_dump"
}

# Acquires an exclusive, non-blocking lock to prevent concurrent restores.
acquire_lock() {
  install -d -m 0700 -o root -g root "$LOCK_DIR"

  exec {LOCK_FD}>"$LOCK_FILE"
  flock -n "$LOCK_FD" || {
    echo 'Backup или восстановление x-ui уже выполняется; операция отменена.' >&2
    exit 1
  }
}

# Restores the previous database and restarts the service after abnormal exit.
cleanup() {
  local rc=$?
  trap - EXIT ERR INT TERM

  if [[ "$SERVICE_STOPPED" == 1 ]]; then
    if [[ "$REPLACED_DB" == 1 && -n "$ROLLBACK_DB" && -f "$ROLLBACK_DB" ]]; then
      if [[ "$(sqlite3 -readonly "$ROLLBACK_DB" 'PRAGMA integrity_check;' 2>/dev/null)" == ok ]]; then
        echo 'Аварийный rollback исходной DB...'

        if mv -f -- "$ROLLBACK_DB" "$DB_PATH"; then
          rm -f -- "${DB_PATH}-wal" "${DB_PATH}-shm" || true
        else
          echo 'Не удалось атомарно опубликовать rollback DB; требуется ручное вмешательство.' >&2
        fi
      else
        echo 'Rollback DB повреждена; автоматический откат пропущен. Требуется ручное вмешательство.' >&2
      fi
    fi

    echo "Запуск $XUI_SERVICE после аварийного завершения..."
    systemctl start "$XUI_SERVICE" || true
  fi

  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    rm -f -- "$TEMP_DIR/passphrase" || true
    rm -rf -- "$TEMP_DIR" || true
  fi

  if ((LOCK_FD >= 0)); then
    flock -u "$LOCK_FD" || true
    exec {LOCK_FD}>&- || true
    LOCK_FD=-1
  fi

  unset BACKUP_PASSPHRASE
  exit "$rc"
}

# Removes leftover .restore_env.* dumps orphaned by an unclean prior exit.
reap_stale_env_dumps() {
  find "$BACKUP_DIR" -maxdepth 1 -type f -name '.restore_env.*' -mmin +60 -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
      [[ "$(stat -c '%U:%G' -- "$f")" == root:root ]] && {
        shred -u -- "$f" 2>/dev/null || rm -f -- "$f"
        echo "Reaped orphaned env dump: $(basename -- "$f")" >&2
      }
    done
}

# Logs the failing command/line for post-mortem, then exits with its status
# explicitly rather than relying on implicit set -e behavior after ERR fires.
on_error() {
  local rc=$?
  echo "Ошибка на строке ${BASH_LINENO[0]}: команда \`${BASH_COMMAND}\`" >&2
  exit "$rc"
}

# Marks interruption by signal so it can be distinguished from a normal error.
on_interrupt() {
  local sig="$1"
  echo 'Получен сигнал прерывания; выполняется корректное завершение...' >&2
  case "$sig" in
    INT) exit 130 ;;
    TERM) exit 143 ;;
    *) exit 130 ;;
  esac
}

# Checks privileges, required files, permissions, tools, and environment values.
validate() {
  [[ $EUID -eq 0 ]] || {
    echo 'Запустите через sudo.'
    exit 1
  }

  [[ -f "$ENV_FILE" ]] || {
    echo 'Не найден файл .env.' >&2
    exit 1
  }

  [[ -f "$DB_PATH" ]] || {
    echo 'Не найдена текущая DB x-ui.' >&2
    exit 1
  }

  [[ "$(stat -c '%U:%G:%a' "$DB_PATH")" == root:root:600 ]] || {
    echo 'Небезопасные права текущей DB.' >&2
    exit 1
  }

  [[ "$(stat -c '%U:%G:%a' "$ENV_FILE")" == root:root:600 ]] || {
    echo 'Небезопасные права .env.' >&2
    exit 1
  }

  [[ "$(stat -c '%U:%G:%a' "$BACKUP_DIR")" == root:root:700 ]] || {
    echo 'Небезопасные права backup-каталога.' >&2
    exit 1
  }

  [[ "$(stat -c '%d' "$BACKUP_DIR")" == "$(stat -c '%d' "$DB_DIR")" ]] || {
    echo 'Каталог backup и каталог DB находятся на разных файловых системах; атомарный restore невозможен.' >&2
    exit 1
  }

  command -v sqlite3 >/dev/null
  command -v gpg >/dev/null
  command -v python3 >/dev/null
  command -v tar >/dev/null
  command -v sha256sum >/dev/null
  command -v flock >/dev/null
  command -v install >/dev/null
  command -v stat >/dev/null
  command -v systemctl >/dev/null

  load_env
  : "${BACKUP_PASSPHRASE:?BACKUP_PASSPHRASE is required}"
}

# Selects the requested archive or the latest matching backup archive.
select_archive() {
  local arg=${1:-}
  local archive hash_file

  if [[ -n "$arg" ]]; then
    arg=$(basename -- "$arg")
    archive="$BACKUP_DIR/$arg"

    [[ "$archive" == "$BACKUP_DIR/"*.tar.gz.gpg && -f "$archive" ]] || {
      echo "Недопустимый архив: $arg"
      exit 1
    }
  else
    local -a restore_archives=()

    mapfile -d '' -t restore_archives < <(
      find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz.gpg' -print0 | sort -z
    )

    ((${#restore_archives[@]} > 0)) || {
      echo 'Бэкапы не найдены.'
      exit 1
    }

    archive="${restore_archives[${#restore_archives[@]} - 1]}"
  fi

  hash_file="${archive}.sha256"

  [[ -f "$hash_file" ]] || {
    echo 'Не найден SHA-256 sidecar.'
    exit 1
  }

  ARCHIVE="$archive"
  HASH_FILE="$hash_file"
}

# Validates archive contents, manifest hashes, SQLite integrity, and table list.
verify_payload() {
  local payload=$1
  local out=$2
  local members

  members="$(tar -tzf "$payload" | LC_ALL=C sort)" || {
    echo 'Не удалось получить список файлов из расшифрованного payload.' >&2
    return 1
  }

  case "$members" in
    $'manifest.json\nx-ui.db' | $'3xui_export.json\nmanifest.json\nx-ui.db')
      ;;
    *)
      echo 'Состав архива не соответствует допустимому формату backup.' >&2
      return 1
      ;;
  esac

  tar -xzf "$payload" -C "$out" --no-same-owner --no-same-permissions || {
    echo 'Не удалось распаковать расшифрованный payload.' >&2
    return 1
  }

  if ! python3 - "$out" <<'PY'
import hashlib
import json
import os
import sqlite3
import stat
import sys
from urllib.parse import quote

workdir = sys.argv[1]
manifest_path = os.path.join(workdir, "manifest.json")
db_path = os.path.join(workdir, "x-ui.db")
json_path = os.path.join(workdir, "3xui_export.json")

def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()

def require_regular_file(path, label):
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        raise SystemExit(f"Missing required file: {label}")
    if not stat.S_ISREG(mode):
        raise SystemExit(f"Expected a regular file: {label}")

def require_sha256(value, label):
    if not isinstance(value, str) or len(value) != 64:
        raise SystemExit(f"Invalid SHA-256 value in manifest: {label}")
    try:
        int(value, 16)
    except ValueError:
        raise SystemExit(f"Invalid SHA-256 value in manifest: {label}")

actual_names = set(os.listdir(workdir))
allowed_names = {"manifest.json", "x-ui.db", "3xui_export.json"}

if not actual_names.issubset(allowed_names):
    raise SystemExit("Unexpected file found after payload extraction")

require_regular_file(manifest_path, "manifest.json")
require_regular_file(db_path, "x-ui.db")

with open(manifest_path, encoding="utf-8") as source:
    manifest = json.load(source)

if manifest.get("format") != "xui-backup-manifest-v2":
    raise SystemExit("Unknown manifest format")

database_sha256 = manifest.get("database_sha256")
require_sha256(database_sha256, "database_sha256")

if digest(db_path) != database_sha256:
    raise SystemExit("Database hash differs from manifest")

tables = manifest.get("tables")
if (
    not isinstance(tables, list)
    or not tables
    or any(not isinstance(name, str) or not name for name in tables)
    or len(set(tables)) != len(tables)
):
    raise SystemExit("Invalid manifest table list")

json_export = manifest.get("json_export", True)
if not isinstance(json_export, bool):
    raise SystemExit("Manifest json_export must be boolean")

json_exists = os.path.exists(json_path)

if json_export:
    require_regular_file(json_path, "3xui_export.json")
    json_sha256 = manifest.get("json_sha256")
    require_sha256(json_sha256, "json_sha256")
    if digest(json_path) != json_sha256:
        raise SystemExit("JSON hash differs from manifest")
else:
    if json_exists:
        raise SystemExit("json_export=false but JSON export file exists")
    if "json_sha256" in manifest:
        raise SystemExit("json_export=false but json_sha256 exists in manifest")

schema_ddl = manifest.get("schema_ddl")
if schema_ddl is not None:
    if not isinstance(schema_ddl, dict):
        raise SystemExit("Invalid manifest schema_ddl")
    if set(schema_ddl) != set(tables):
        raise SystemExit("Manifest schema_ddl table set differs from tables")
    if any(not isinstance(value, str) for value in schema_ddl.values()):
        raise SystemExit("Manifest schema_ddl contains a non-string DDL value")

row_counts = manifest.get("row_counts")
if row_counts is not None:
    if not isinstance(row_counts, dict):
        raise SystemExit("Invalid manifest row_counts")
    if set(row_counts) != set(tables):
        raise SystemExit("Manifest row_counts table set differs from tables")
    if any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        for value in row_counts.values()
    ):
        raise SystemExit("Manifest row_counts contains an invalid value")

connection = sqlite3.connect(
    "file:" + quote(db_path) + "?mode=ro",
    uri=True,
)
try:
    restored_tables = sorted(
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_schema "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name"
        )
    )
finally:
    connection.close()

if restored_tables != sorted(tables):
    raise SystemExit("Manifest table list differs from DB")
PY
  then
    echo 'Manifest или содержимое расшифрованного payload не прошло проверку.' >&2
    return 1
  fi

  if [[ "$(sqlite3 -readonly "$out/x-ui.db" 'PRAGMA integrity_check;')" != ok ]]; then
    echo 'SQLite integrity_check расшифрованной DB завершился ошибкой.' >&2
    return 1
  fi

  return 0
}

# Prints verified backup metadata before any destructive restore action.
print_restore_preflight() {
  local manifest_path=$1
  local archive_path=$2

  python3 - "$manifest_path" "$archive_path" <<'PY'
import json
import os
import sys

manifest_path, archive_path = sys.argv[1:3]

with open(manifest_path, encoding="utf-8") as source:
    manifest = json.load(source)

def value(name):
    return json.dumps(manifest.get(name), ensure_ascii=False)

tables = manifest.get("tables", [])
row_counts = manifest.get("row_counts", {})

json_export = manifest.get("json_export", True)

if "json_export" in manifest:
    json_export_label = json.dumps(json_export)
else:
    json_export_label = "true (legacy manifest default)"

print()
print("===== RESTORE PREFLIGHT =====")
print(f"Archive: {os.path.basename(archive_path)}")
print(f"Archive size (bytes): {os.path.getsize(archive_path)}")
print(f"Created UTC: {value('created_at_utc')}")
print(f"Hostname: {value('hostname')}")
print(f"Backup script version: {value('script_version')}")
print(f"SQLite version: {value('sqlite_version')}")
print(f"Database file: {value('database_file')}")
print(f"JSON export enabled: {json_export_label}")
print(f"Application tables: {len(tables)}")

if isinstance(row_counts, dict):
    total_rows = sum(
        count
        for count in row_counts.values()
        if isinstance(count, int) and not isinstance(count, bool)
    )
    print(f"Manifest row count total: {total_rows}")

print("Backup table list:")
for table in sorted(tables):
    print(f"  {table}")

print("Backup SQLite integrity: OK")
print("=============================")
PY
}

# Compares application-table names and DDL between current and backup databases.
# Returns 0 for full schema match, 10 for a detected mismatch, and another
# non-zero code for a technical comparison failure.
compare_schema() {
  local current_db=$1
  local backup_db=$2

  python3 - "$current_db" "$backup_db" <<'PY'
import sqlite3
import sys
from urllib.parse import quote

current_path, backup_path = sys.argv[1:3]

def read_schema(path):
    connection = sqlite3.connect(
        "file:" + quote(path) + "?mode=ro",
        uri=True,
    )
    try:
        return {
            name: ddl or ""
            for name, ddl in connection.execute(
                "SELECT name, sql "
                "FROM sqlite_schema "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
        }
    finally:
        connection.close()

current = read_schema(current_path)
backup = read_schema(backup_path)

only_current = sorted(set(current) - set(backup))
only_backup = sorted(set(backup) - set(current))
ddl_differs = sorted(
    name
    for name in set(current) & set(backup)
    if current[name] != backup[name]
)

if not only_current and not only_backup and not ddl_differs:
    print("Schema comparison: MATCH")
    raise SystemExit(0)

print("Schema comparison: MISMATCH")

if only_current:
    print("Only in current DB:")
    for name in only_current:
        print(f"  {name}")

if only_backup:
    print("Only in backup DB:")
    for name in only_backup:
        print(f"  {name}")

if ddl_differs:
    print("DDL differs:")
    for name in ddl_differs:
        print(f"  {name}")

raise SystemExit(10)
PY
}

# ------------------------------------------------------------------------------
# 3. Core Restore Logic
# ------------------------------------------------------------------------------

# Performs archive verification, database replacement, and rollback-protected restart.
main() {
  trap cleanup EXIT
  trap on_error ERR
  trap 'on_interrupt INT' INT
  trap 'on_interrupt TERM' TERM

  reap_stale_env_dumps

  acquire_lock

  validate

  select_archive "${1:-}"

  echo "Выбран архив: $ARCHIVE"
  echo 'Будут выполнены SHA-256, GPG, manifest, JSON, SQLite integrity и rollback-защита.'

  (
    cd "$BACKUP_DIR" &&
      sha256sum -c --status "$(basename "$HASH_FILE")"
  ) || {
    echo 'SHA-256 не совпадает.'
    exit 1
  }

  echo 'SHA-256: OK'

  TEMP_DIR="$(mktemp -d "${BACKUP_DIR}/.restore_work.XXXXXX")"
  chmod 700 "$TEMP_DIR"
  printf %s "$BACKUP_PASSPHRASE" >"$TEMP_DIR/passphrase"
  chmod 600 "$TEMP_DIR/passphrase"
  unset BACKUP_PASSPHRASE

  local payload="$TEMP_DIR/payload.tar.gz"
  local out="$TEMP_DIR/payload"
  local restore_new="$TEMP_DIR/x-ui.db.restore.new"
  local owner
  local group
  local mode
  local schema_rc=0
  local schema_answer
  local answer

  mkdir -m 700 "$out"

  gpg --batch --yes --pinentry-mode loopback --no-symkey-cache \
    --passphrase-file "$TEMP_DIR/passphrase" \
    --output "$payload" \
    --decrypt "$ARCHIVE"

  rm -f -- "$TEMP_DIR/passphrase"

  verify_payload "$payload" "$out" || {
    echo 'Проверка расшифрованного backup не пройдена.'
    exit 1
  }

  if [[ "$(sqlite3 -readonly "$DB_PATH" 'PRAGMA integrity_check;')" != ok ]]; then
    echo 'Текущая DB не проходит SQLite integrity_check; восстановление отменено.' >&2
    exit 1
  fi

  print_restore_preflight "$out/manifest.json" "$ARCHIVE" || {
    echo 'Не удалось вывести проверенные metadata backup.' >&2
    exit 1
  }

  schema_rc=0
  compare_schema "$DB_PATH" "$out/x-ui.db" || schema_rc=$?

  if ((schema_rc == 10)); then
    echo
    echo 'ВНИМАНИЕ: схема backup отличается от текущей рабочей DB.'
    echo 'Продолжение может потребовать миграции 3x-ui после запуска сервиса.'

    if ! read -r -p 'Для подтверждения восстановления при различии схемы введите строго YES: ' schema_answer; then
      echo
      echo 'Отменено: не получено подтверждение YES.'
      exit 0
    fi

    if [[ "$schema_answer" != YES ]]; then
      echo 'Отменено: подтверждение YES не получено.'
      exit 0
    fi
  elif ((schema_rc != 0)); then
    echo 'Не удалось сравнить schema текущей и backup DB.' >&2
    exit "$schema_rc"
  fi

  echo
  echo 'Все проверки backup успешно пройдены.'
  echo "Будет остановлен $XUI_SERVICE, создан rollback текущей DB и выполнена атомарная замена."

  if ! read -r -p 'Для продолжения введите строго RESTORE: ' answer; then
    echo
    echo 'Отменено: не получено подтверждение RESTORE.'
    exit 0
  fi

  if [[ "$answer" != RESTORE ]]; then
    echo 'Отменено.'
    exit 0
  fi

  owner=$(stat -c %u "$DB_PATH")
  group=$(stat -c %g "$DB_PATH")
  mode=$(stat -c %a "$DB_PATH")

  echo "Остановка $XUI_SERVICE..."
  systemctl stop "$XUI_SERVICE"
  SERVICE_STOPPED=1

  ROLLBACK_DB="$TEMP_DIR/before-restore.db"

  local rollback_escaped="${ROLLBACK_DB//\'/\'\'}"
  sqlite3 "$DB_PATH" <<SQL
.timeout 8000
.backup '${rollback_escaped}'
SQL

  [[ "$(sqlite3 -readonly "$ROLLBACK_DB" 'PRAGMA integrity_check;')" == ok ]] || {
    echo 'Rollback DB повреждена.'
    exit 1
  }

  install -o "$owner" -g "$group" -m "$mode" "$out/x-ui.db" "$restore_new"

  if [[ "$(sqlite3 -readonly "$restore_new" 'PRAGMA integrity_check;')" != ok ]]; then
    echo 'Подготовленная DB для публикации не проходит integrity_check.' >&2
    exit 1
  fi

  mv -f -- "$restore_new" "$DB_PATH"
  REPLACED_DB=1

  rm -f -- "${DB_PATH}-wal" "${DB_PATH}-shm"

  systemctl start "$XUI_SERVICE"

  local -i attempt=0
  until systemctl is-active --quiet "$XUI_SERVICE"; do
    ((attempt++))
    if ((attempt >= 15)); then
      echo 'Сервис не запустился за отведённое время; выполнится rollback.' >&2
      exit 1
    fi
    sleep 1
  done

  SERVICE_STOPPED=0
  REPLACED_DB=0

  echo 'Восстановление успешно завершено.'
  echo "Application tables: $(sqlite3 -readonly "$DB_PATH" "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%';")"
}

# ------------------------------------------------------------------------------
# 4. Entrypoint
# ------------------------------------------------------------------------------

main "$@"
