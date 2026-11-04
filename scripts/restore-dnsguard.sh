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
BACKUP_MODE="${DNSGUARD_BACKUP_MODE:-docker}"
RESTORE_INCLUDE_SENSITIVE="${RESTORE_INCLUDE_SENSITIVE:-false}"
DNSGUARD_DATA_DIR="${DNSGUARD_DATA_DIR:-$ROOT/docker-data}"
DNSGUARD_SECRET_DIR="${DNSGUARD_SECRET_DIR:-$ROOT/secrets}"
DNSGUARD_TLS_DIR="${DNSGUARD_TLS_DIR:-$ROOT/tls}"
COMPOSE_ENV_FILE="${DNSGUARD_ENV_FILE:-$ROOT/deploy/docker/dnsguard.env}"
[[ -n "$ARCHIVE" && -f "$ARCHIVE" ]] || { echo "Usage: $0 BACKUP_ARCHIVE" >&2; exit 2; }
[[ "$BACKUP_MODE" == docker ]] || { echo "DNSGUARD_BACKUP_MODE must be docker; DNSGuard V1.0 production restores are Docker Compose only" >&2; exit 2; }

if command -v docker >/dev/null 2>&1 && [[ -f "$COMPOSE_ENV_FILE" ]] && docker compose --env-file "$COMPOSE_ENV_FILE" -f "$ROOT/compose.yaml" ps --status running -q 2>/dev/null | grep -q .; then
  echo "Stop the Docker Compose services before restoring files" >&2
  exit 1
fi

export ARCHIVE ROOT BACKUP_MODE RESTORE_INCLUDE_SENSITIVE
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
mode = os.environ["BACKUP_MODE"]
restore_sensitive = os.environ.get("RESTORE_INCLUDE_SENSITIVE", "false").lower() == "true"
docker_roots = {
    "docker-data": Path(os.environ["DNSGUARD_DATA_DIR"]).expanduser().resolve(),
    "secrets": Path(os.environ["DNSGUARD_SECRET_DIR"]).expanduser().resolve(),
    "tls": Path(os.environ["DNSGUARD_TLS_DIR"]).expanduser().resolve(),
}

def destination_for(relative: Path) -> tuple[Path, bool]:
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
    if manifest.get("mode") != mode:
        raise SystemExit(f"backup mode mismatch: archive={manifest.get('mode')} requested={mode}")
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
            os.chmod(source, members_by_name[str(relative)].mode & 0o7777)
            owner = None
            if mode == "docker":
                if relative.parts[0] in {"docker-data", "secrets"}:
                    owner = (10001, 10001)
                elif relative.parts[0] == "tls":
                    owner = (101, 101)
            planned.append((source, destination, members_by_name[str(relative)].mode & 0o7777, owner))
        for source, destination, mode_bits, owner in planned:
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + ".restore.tmp")
            shutil.copy2(source, temporary)
            os.chmod(temporary, mode_bits)
            if owner is not None and os.geteuid() == 0:
                os.chown(temporary, *owner)
            os.replace(temporary, destination)
        if mode == "docker" and os.geteuid() == 0:
            for root_name, owner in (("docker-data", (10001, 10001)), ("secrets", (10001, 10001)), ("tls", (101, 101))):
                root_dir = docker_roots[root_name]
                if not root_dir.exists():
                    continue
                for current, directories, _ in os.walk(root_dir):
                    os.chown(current, *owner)
                    os.chmod(current, 0o750)
                    for directory in directories:
                        path = Path(current) / directory
                        os.chown(path, *owner)
                        os.chmod(path, 0o750)
            print(f"restored {destination}")
PY
