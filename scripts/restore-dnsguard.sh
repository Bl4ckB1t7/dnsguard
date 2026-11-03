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
if [[ -z "$ARCHIVE" || ! -f "$ARCHIVE" ]]; then
  echo "Usage: $0 BACKUP_ARCHIVE" >&2
  exit 2
fi
if [[ -f "$ROOT/.run/api.pid" ]] && kill -0 "$(cat "$ROOT/.run/api.pid")" 2>/dev/null; then
  echo "Stop DNSGuard API before restoring files" >&2
  exit 1
fi
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet dnsguard-api.service 2>/dev/null; then
  echo "Stop dnsguard-api.service before restoring files" >&2
  exit 1
fi

DNS_STATE_FILE="${DNS_STATE_FILE:-$ROOT/data/dns-state.json}"
DNS_NODE_CONFIG_FILE="${DNS_NODE_CONFIG_FILE:-$ROOT/config/dns-nodes.json}"
AUDIT_FILE="${AUDIT_FILE:-$ROOT/data/audit.json}"
RPZ_ARTIFACT_FILE="${RPZ_ARTIFACT_FILE:-$ROOT/data/rpz/rpz.local.db}"
AUTH_FILE="${AUTH_FILE:-$ROOT/.run/auth.json}"
RPZ_KEY_FILE="${RPZ_KEY_FILE:-}"
export ARCHIVE ROOT DNS_STATE_FILE DNS_NODE_CONFIG_FILE AUDIT_FILE RPZ_ARTIFACT_FILE AUTH_FILE RPZ_KEY_FILE
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
allowed = set()
for key in ("DNS_STATE_FILE", "DNS_NODE_CONFIG_FILE", "AUDIT_FILE", "RPZ_ARTIFACT_FILE", "AUTH_FILE", "RPZ_KEY_FILE"):
    raw = os.environ.get(key, "")
    if raw:
        path = Path(raw).expanduser()
        allowed.add((path if path.is_absolute() else root / path).resolve())
with tarfile.open(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    for member in members:
        name = Path(member.name)
        if name.is_absolute() or ".." in name.parts or member.issym() or member.islnk() or not member.isfile():
            raise SystemExit(f"unsafe backup member: {member.name}")
    try:
        manifest_member = bundle.getmember("manifest.json")
        manifest = json.loads(bundle.extractfile(manifest_member).read())
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid backup manifest: {exc}")
    if manifest.get("format") != 1:
        raise SystemExit("unsupported backup format")
    members_by_name = {member.name: member for member in members}
    with tempfile.TemporaryDirectory(prefix="dnsguard-restore-") as temp:
        stage = Path(temp)
        for entry in manifest.get("files", []):
            relative = Path(entry["path"])
            destination = (Path("/") / relative).resolve()
            if relative.is_absolute() or ".." in relative.parts or str(relative) not in members_by_name or destination not in allowed:
                raise SystemExit(f"invalid manifest path: {relative}")
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(members_by_name[str(relative)])
            destination.write_bytes(source.read())
            if hashlib.sha256(destination.read_bytes()).hexdigest() != entry["sha256"]:
                raise SystemExit(f"checksum mismatch: {relative}")
        for entry in manifest["files"]:
            relative = Path(entry["path"])
            source = stage / relative
            destination = (Path("/") / relative).resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + ".restore.tmp")
            shutil.copy2(source, temporary)
            os.replace(temporary, destination)
            print(f"restored {destination}")
PY
