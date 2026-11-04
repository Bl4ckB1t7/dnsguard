#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${DNSGUARD_ENV_FILE:-}" && -f "$DNSGUARD_ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$DNSGUARD_ENV_FILE"
  set +a
fi

BACKUP_MODE="${DNSGUARD_BACKUP_MODE:-docker}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/dnsguard}"
BACKUP_INCLUDE_SENSITIVE="${BACKUP_INCLUDE_SENSITIVE:-false}"
BACKUP_RETENTION_COUNT="${BACKUP_RETENTION_COUNT:-14}"
DNSGUARD_DATA_DIR="${DNSGUARD_DATA_DIR:-$ROOT/docker-data}"
DNSGUARD_SECRET_DIR="${DNSGUARD_SECRET_DIR:-$ROOT/secrets}"
DNSGUARD_TLS_DIR="${DNSGUARD_TLS_DIR:-$ROOT/tls}"
DNSGUARD_ENV_FILE="${DNSGUARD_ENV_FILE:-$ROOT/deploy/docker/dnsguard.env}"

[[ "$BACKUP_MODE" == docker ]] || {
  echo "DNSGUARD_BACKUP_MODE must be docker; DNSGuard V1.0 production backups are Docker Compose only" >&2
  exit 2
}
export BACKUP_DIR BACKUP_MODE
export BACKUP_INCLUDE_SENSITIVE BACKUP_RETENTION_COUNT DNSGUARD_DATA_DIR DNSGUARD_SECRET_DIR DNSGUARD_TLS_DIR DNSGUARD_ENV_FILE

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

mode = os.environ["BACKUP_MODE"]
backup_dir = Path(os.environ["BACKUP_DIR"]).expanduser().resolve()
backup_dir.mkdir(parents=True, exist_ok=True)
backup_dir.chmod(0o700)
timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
archive = backup_dir / f"dnsguard-{timestamp}.tar.gz"
manifest = {"format": 2, "mode": mode, "createdAt": datetime.now(timezone.utc).isoformat(), "files": []}

def archive_path(source: Path, root: Path | None, prefix: str | None) -> Path:
    if root is not None:
        return Path(prefix or "") / source.relative_to(root)
    if prefix is not None:
        return Path(prefix)
    return Path(str(source).lstrip("/"))

def add_file(stage: Path, source: Path, root: Path | None = None, prefix: str | None = None, sensitive: bool = False) -> None:
    source = source.expanduser()
    if not source.is_absolute():
        source = Path.cwd() / source
    source = source.resolve()
    if not source.is_file() or source.is_symlink():
        return
    relative = archive_path(source, root, prefix)
    destination = stage / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    manifest["files"].append({"path": str(relative), "sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "sensitive": sensitive})

def add_tree(stage: Path, source_root: Path, prefix: str, sensitive: bool = False) -> None:
    source_root = source_root.expanduser().resolve()
    if not source_root.is_dir():
        return
    for source in sorted(source_root.rglob("*")):
        if not source.is_file() or source.is_symlink() or source.suffix in {".lock", ".tmp", ".pid"}:
            continue
        add_file(stage, source, source_root, prefix, sensitive)

with tempfile.TemporaryDirectory(prefix="dnsguard-backup-") as temp:
    stage = Path(temp)
    if mode == "docker":
        # These are host paths. The application paths /var/lib/dnsguard and
        # /run/dnsguard-secrets must not be used by a host-side backup.
        add_tree(stage, Path(os.environ["DNSGUARD_DATA_DIR"]), "docker-data", False)
        if os.environ.get("BACKUP_INCLUDE_SENSITIVE", "false").lower() == "true":
            add_tree(stage, Path(os.environ["DNSGUARD_SECRET_DIR"]), "secrets", True)
            add_tree(stage, Path(os.environ["DNSGUARD_TLS_DIR"]), "tls", True)
            env_file = Path(os.environ["DNSGUARD_ENV_FILE"]).expanduser().resolve()
            if not env_file.is_file() or env_file.is_symlink():
                raise SystemExit(f"sensitive backup requires a regular Docker env file: {env_file}")
            add_file(stage, env_file, None, "config/dnsguard.env", True)
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
