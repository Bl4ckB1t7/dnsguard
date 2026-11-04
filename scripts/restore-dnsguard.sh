#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${DNSGUARD_ENV_FILE:-}" && -f "$DNSGUARD_ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$DNSGUARD_ENV_FILE"
  set +a
fi

ARCHIVE="${1:-}"
BACKUP_MODE="${DNSGUARD_BACKUP_MODE:-${BACKUP_MODE:-systemd}}"
RESTORE_INCLUDE_SENSITIVE="${RESTORE_INCLUDE_SENSITIVE:-false}"
DNSGUARD_DATA_DIR="${DNSGUARD_DATA_DIR:-$ROOT/docker-data}"
DNSGUARD_SECRET_DIR="${DNSGUARD_SECRET_DIR:-$ROOT/secrets}"
DNSGUARD_TLS_DIR="${DNSGUARD_TLS_DIR:-$ROOT/tls}"
COMPOSE_ENV_FILE="${DNSGUARD_ENV_FILE:-$ROOT/deploy/docker/dnsguard.env}"
[[ -n "$ARCHIVE" && -f "$ARCHIVE" ]] || { echo "Usage: $0 BACKUP_ARCHIVE" >&2; exit 2; }
[[ "$BACKUP_MODE" == systemd || "$BACKUP_MODE" == docker ]] || { echo "DNSGUARD_BACKUP_MODE must be systemd or docker" >&2; exit 2; }

if [[ "$BACKUP_MODE" == docker ]]; then
  if command -v docker >/dev/null 2>&1 && [[ -f "$COMPOSE_ENV_FILE" ]] && docker compose --env-file "$COMPOSE_ENV_FILE" -f "$ROOT/compose.yaml" ps --status running -q 2>/dev/null | grep -q .; then
    echo "Stop the Docker Compose services before restoring files" >&2
    exit 1
  fi
else
  if [[ -f "$ROOT/.run/api.pid" ]] && kill -0 "$(cat "$ROOT/.run/api.pid")" 2>/dev/null; then
    echo "Stop DNSGuard API before restoring files" >&2
    exit 1
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet dnsguard-api.service 2>/dev/null; then
    echo "Stop dnsguard-api.service before restoring files" >&2
    exit 1
  fi
fi

DNS_STATE_FILE="${DNS_STATE_FILE:-$ROOT/data/dns-state.json}"
DNS_NODE_CONFIG_FILE="${DNS_NODE_CONFIG_FILE:-$ROOT/config/dns-nodes.json}"
AUDIT_FILE="${AUDIT_FILE:-$ROOT/data/audit.json}"
RPZ_ARTIFACT_FILE="${RPZ_ARTIFACT_FILE:-$ROOT/data/rpz/rpz.local.db}"
AUTH_FILE="${AUTH_FILE:-$ROOT/.run/auth.json}"
RPZ_KEY_FILE="${RPZ_KEY_FILE:-}"
export ARCHIVE ROOT BACKUP_MODE RESTORE_INCLUDE_SENSITIVE DNS_STATE_FILE DNS_NODE_CONFIG_FILE AUDIT_FILE RPZ_ARTIFACT_FILE AUTH_FILE RPZ_KEY_FILE
export DNSGUARD_DATA_DIR DNSGUARD_SECRET_DIR DNSGUARD_TLS_DIR

python3 - <<'PY'
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path

archive = Path(os.environ["ARCHIVE"]).expanduser().resolve()
root = Path(os.environ["ROOT"]).resolve()
mode = os.environ["BACKUP_MODE"]
restore_sensitive = os.environ.get("RESTORE_INCLUDE_SENSITIVE", "false").lower() == "true"
allowed_files = set()
allowed_roots = []
for key in ("DNS_STATE_FILE", "DNS_NODE_CONFIG_FILE", "AUDIT_FILE", "RPZ_ARTIFACT_FILE", "AUTH_FILE", "RPZ_KEY_FILE"):
    raw = os.environ.get(key, "")
    if raw:
        path = Path(raw).expanduser()
        path = (path if path.is_absolute() else root / path).resolve()
        allowed_files.add(path)
        allowed_roots.append(path.parent)

docker_roots = {
    "docker-data": Path(os.environ["DNSGUARD_DATA_DIR"]).expanduser().resolve(),
    "secrets": Path(os.environ["DNSGUARD_SECRET_DIR"]).expanduser().resolve(),
    "tls": Path(os.environ["DNSGUARD_TLS_DIR"]).expanduser().resolve(),
}

def destination_for(relative: Path) -> tuple[Path, bool]:
    if mode == "docker":
        if not relative.parts or relative.parts[0] not in docker_roots:
            raise SystemExit(f"invalid Docker backup path: {relative}")
        sensitive = relative.parts[0] in {"secrets", "tls"}
        if sensitive and not restore_sensitive:
            raise SystemExit(f"sensitive entry requires RESTORE_INCLUDE_SENSITIVE=true: {relative}")
        root_dir = docker_roots[relative.parts[0]]
        destination = root_dir.joinpath(*relative.parts[1:]).resolve()
        if destination != root_dir and root_dir not in destination.parents:
            raise SystemExit(f"path escapes Docker restore root: {relative}")
        return destination, sensitive
    destination = (Path("/") / relative).resolve()
    if destination not in allowed_files and not any(parent in destination.parents for parent in allowed_roots):
        raise SystemExit(f"manifest path is outside configured restore paths: {relative}")
    return destination, False

with tarfile.open(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    for member in members:
        name = Path(member.name)
        if name.is_absolute() or ".." in name.parts or member.issym() or member.islnk() or not member.isfile():
            raise SystemExit(f"unsafe backup member: {member.name}")
    try:
        manifest = json.loads(bundle.extractfile(bundle.getmember("manifest.json")).read())
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid backup manifest: {exc}")
    if manifest.get("format") not in (1, 2):
        raise SystemExit("unsupported backup format")
    if manifest.get("mode", "systemd") != mode:
        raise SystemExit(f"backup mode mismatch: archive={manifest.get('mode', 'systemd')} requested={mode}")
    members_by_name = {member.name: member for member in members}
    with tempfile.TemporaryDirectory(prefix="dnsguard-restore-") as temp:
        stage = Path(temp)
        planned = []
        for entry in manifest.get("files", []):
            relative = Path(entry["path"])
            if str(relative) not in members_by_name:
                raise SystemExit(f"manifest member missing: {relative}")
            destination, _ = destination_for(relative)
            source = stage / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            extracted = bundle.extractfile(members_by_name[str(relative)])
            source.write_bytes(extracted.read())
            if hashlib.sha256(source.read_bytes()).hexdigest() != entry["sha256"]:
                raise SystemExit(f"checksum mismatch: {relative}")
            planned.append((source, destination))
        for source, destination in planned:
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + ".restore.tmp")
            shutil.copy2(source, temporary)
            os.replace(temporary, destination)
            print(f"restored {destination}")
PY
