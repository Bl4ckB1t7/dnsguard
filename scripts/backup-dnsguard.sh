#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${DNSGUARD_ENV_FILE:-}" && -f "$DNSGUARD_ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$DNSGUARD_ENV_FILE"
  set +a
fi

BACKUP_DIR="${BACKUP_DIR:-/var/backups/dnsguard}"
DNS_STATE_FILE="${DNS_STATE_FILE:-$ROOT/data/dns-state.json}"
DNS_NODE_CONFIG_FILE="${DNS_NODE_CONFIG_FILE:-$ROOT/config/dns-nodes.json}"
AUDIT_FILE="${AUDIT_FILE:-$ROOT/data/audit.json}"
RPZ_ARTIFACT_FILE="${RPZ_ARTIFACT_FILE:-$ROOT/data/rpz/rpz.local.db}"
AUTH_FILE="${AUTH_FILE:-$ROOT/.run/auth.json}"
RPZ_KEY_FILE="${RPZ_KEY_FILE:-}"
BACKUP_INCLUDE_SENSITIVE="${BACKUP_INCLUDE_SENSITIVE:-false}"
BACKUP_RETENTION_COUNT="${BACKUP_RETENTION_COUNT:-14}"
export BACKUP_DIR DNS_STATE_FILE DNS_NODE_CONFIG_FILE AUDIT_FILE RPZ_ARTIFACT_FILE AUTH_FILE RPZ_KEY_FILE BACKUP_INCLUDE_SENSITIVE BACKUP_RETENTION_COUNT

command -v python3 >/dev/null 2>&1 || { echo "Missing required command: python3" >&2; exit 2; }
python3 - <<'PY'
import hashlib
import json
import os
import shutil
import stat
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

backup_dir = Path(os.environ["BACKUP_DIR"]).expanduser()
backup_dir.mkdir(parents=True, exist_ok=True)
backup_dir.chmod(0o700)
timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
archive = backup_dir / f"dnsguard-{timestamp}.tar.gz"
files = [
    (os.environ["DNS_STATE_FILE"], False),
    (os.environ["DNS_NODE_CONFIG_FILE"], False),
    (os.environ["AUDIT_FILE"], False),
    (os.environ["RPZ_ARTIFACT_FILE"], False),
]
if os.environ.get("BACKUP_INCLUDE_SENSITIVE", "false").lower() == "true":
    files.extend([(os.environ["AUTH_FILE"], True), (os.environ.get("RPZ_KEY_FILE", ""), True)])

manifest = {"format": 1, "createdAt": datetime.now(timezone.utc).isoformat(), "files": []}
with tempfile.TemporaryDirectory(prefix="dnsguard-backup-") as temp:
    stage = Path(temp)
    for raw_path, sensitive in files:
        if not raw_path:
            continue
        source = Path(raw_path).expanduser()
        if not source.is_absolute():
            source = Path.cwd() / source
        source = source.resolve()
        if not source.is_file():
            continue
        relative = Path(str(source).lstrip("/"))
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        manifest["files"].append({"path": str(relative), "sha256": digest, "sensitive": sensitive})
    if not manifest["files"]:
        raise SystemExit("no configured DNSGuard files were found")
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    temporary = archive.with_suffix(archive.suffix + ".tmp")
    with tarfile.open(temporary, "w:gz") as bundle:
        bundle.add(stage / "manifest.json", arcname="manifest.json")
        for item in manifest["files"]:
            bundle.add(stage / item["path"], arcname=item["path"])
    os.replace(temporary, archive)
    archive.chmod(stat.S_IRUSR | stat.S_IWUSR)
retention = int(os.environ.get("BACKUP_RETENTION_COUNT", "14"))
if retention < 1 or retention > 1000:
    retention = 14
archives = sorted(backup_dir.glob("dnsguard-*.tar.gz"), key=lambda item: item.stat().st_mtime, reverse=True)
for old_archive in archives[retention:]:
    old_archive.unlink()
print(archive)
PY
