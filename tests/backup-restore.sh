#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dnsguard-backup-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

make_fixture() {
  local data="$1" secrets="$2" tls="$3"
  mkdir -p "$data/rpz" "$secrets" "$tls"
  printf '%s\n' '{"rules":[{"domain":"restore.example.com"}]}' >"$data/dns-state.json"
  printf '%s\n' '{"rules":[{"domain":"old.example.com"}]}' >"$data/dns-state.json.bak"
  printf '%s\n' '[{"id":"job-1","status":"succeeded"}]' >"$data/publish-jobs.json"
  printf '%s\n' '[{"hash":"audit-hash"}]' >"$data/audit.json"
  printf '%s\n' '[{"hash":"previous-audit-hash"}]' >"$data/audit.json.1"
  printf '%s\n' '{"status":"completed"}' >"$data/initialization.json"
  printf '%s\n' '{"username":"admin","passwordHash":"$2a$10$fixture"}' >"$data/auth.json"
  printf '%s\n' '{"enabled":false}' >"$data/telegram.json"
  printf '%s\n' 'zone artifact' >"$data/rpz/rpz.local.db"
  printf '%s\n' 'key fixture' >"$secrets/rpz-manager.key"
  printf '%s\n' 'certificate fixture' >"$tls/fullchain.pem"
  printf '%s\n' 'private key fixture' >"$tls/privkey.pem"
  chmod 0600 "$secrets/rpz-manager.key" "$tls/privkey.pem"
  chmod 0644 "$tls/fullchain.pem"
}

data="$WORK/docker-data"
secrets="$WORK/secrets"
tls="$WORK/tls"
backup_dir="$WORK/backups"
restore_data="$WORK/restored-docker-data"
restore_secrets="$WORK/restored-secrets"
restore_tls="$WORK/restored-tls"
make_fixture "$data" "$secrets" "$tls"

archive="$(DNSGUARD_BACKUP_MODE=docker \
  DNSGUARD_DATA_DIR="$data" \
  DNSGUARD_SECRET_DIR="$secrets" \
  DNSGUARD_TLS_DIR="$tls" \
  BACKUP_INCLUDE_SENSITIVE=true \
  BACKUP_DIR="$backup_dir" \
  "$ROOT/scripts/backup-dnsguard.sh")"

[[ -f "$archive" ]]
[[ "$(stat -c '%a' "$archive")" == 600 ]]
python3 - "$archive" <<'PY'
import json, sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as bundle:
    manifest = json.loads(bundle.extractfile("manifest.json").read())
    assert manifest["format"] == 2 and manifest["mode"] == "docker"
    names = {item["path"] for item in manifest["files"]}
    required = {
        "docker-data/dns-state.json",
        "docker-data/dns-state.json.bak",
        "docker-data/publish-jobs.json",
        "docker-data/audit.json.1",
        "docker-data/initialization.json",
        "docker-data/auth.json",
        "docker-data/telegram.json",
        "docker-data/rpz/rpz.local.db",
        "secrets/rpz-manager.key",
        "tls/privkey.pem",
    }
    assert required <= names, sorted(required - names)
PY

mkdir -p "$restore_data" "$restore_secrets" "$restore_tls"
DNSGUARD_BACKUP_MODE=docker \
DNSGUARD_DATA_DIR="$restore_data" \
DNSGUARD_SECRET_DIR="$restore_secrets" \
DNSGUARD_TLS_DIR="$restore_tls" \
RESTORE_INCLUDE_SENSITIVE=true \
"$ROOT/scripts/restore-dnsguard.sh" "$archive" >/dev/null
cmp "$data/dns-state.json" "$restore_data/dns-state.json"
cmp "$data/dns-state.json.bak" "$restore_data/dns-state.json.bak"
cmp "$data/publish-jobs.json" "$restore_data/publish-jobs.json"
cmp "$data/audit.json.1" "$restore_data/audit.json.1"
cmp "$data/auth.json" "$restore_data/auth.json"
cmp "$secrets/rpz-manager.key" "$restore_secrets/rpz-manager.key"
cmp "$tls/privkey.pem" "$restore_tls/privkey.pem"

if DNSGUARD_BACKUP_MODE=docker \
  DNSGUARD_DATA_DIR="$WORK/unsafe-data" \
  DNSGUARD_SECRET_DIR="$WORK/unsafe-secrets" \
  DNSGUARD_TLS_DIR="$WORK/unsafe-tls" \
  RESTORE_INCLUDE_SENSITIVE=false \
  "$ROOT/scripts/restore-dnsguard.sh" "$archive" >/dev/null 2>&1; then
  echo 'restore unexpectedly accepted sensitive files without explicit opt-in' >&2
  exit 1
fi

echo 'PASS: Docker backup contains complete state and sensitive files restore only with explicit opt-in'
