#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/docker-paths.sh"
DNSGUARD_ENV_FILE="$(dnsguard_resolve_path "${DNSGUARD_ENV_FILE:-$ROOT/deploy/docker/dnsguard.env}" "$ROOT")"
if [[ -f "$DNSGUARD_ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$DNSGUARD_ENV_FILE"
  set +a
fi

ARCHIVE="${1:-}"
BACKUP_MODE="${DNSGUARD_BACKUP_MODE:-docker}"
RESTORE_INCLUDE_SENSITIVE="${RESTORE_INCLUDE_SENSITIVE:-false}"
RESTORE_ALLOW_OVERWRITE="${RESTORE_ALLOW_OVERWRITE:-false}"
dnsguard_prepare_paths "$ROOT"
COMPOSE_ENV_FILE="$DNSGUARD_ENV_FILE"
[[ -n "$ARCHIVE" && -f "$ARCHIVE" ]] || { echo "Usage: $0 BACKUP_ARCHIVE" >&2; exit 2; }
[[ "$BACKUP_MODE" == docker ]] || { echo "DNSGUARD_BACKUP_MODE must be docker; DNSGuard V1.0 production restores are Docker Compose only" >&2; exit 2; }

if command -v docker >/dev/null 2>&1 && [[ -f "$COMPOSE_ENV_FILE" ]] && docker compose --env-file "$COMPOSE_ENV_FILE" -f "$ROOT/compose.yaml" ps --status running -q 2>/dev/null | grep -q .; then
  echo "Stop the Docker Compose services before restoring files" >&2
  exit 1
fi

export ARCHIVE ROOT BACKUP_MODE RESTORE_INCLUDE_SENSITIVE RESTORE_ALLOW_OVERWRITE
export DNSGUARD_DATA_DIR DNSGUARD_SECRET_DIR DNSGUARD_TLS_DIR DNSGUARD_ENV_FILE

python3 - <<'PY'
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

archive = Path(os.environ["ARCHIVE"]).expanduser().resolve()
mode = os.environ["BACKUP_MODE"]
restore_sensitive = os.environ.get("RESTORE_INCLUDE_SENSITIVE", "false").lower() == "true"
allow_overwrite = os.environ.get("RESTORE_ALLOW_OVERWRITE", "false").lower() == "true"

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_FILES = 10000
MAX_SINGLE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024

def bounded_limit(name, default, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(1, min(value, maximum))

max_archive_bytes = bounded_limit("RESTORE_MAX_ARCHIVE_BYTES", MAX_ARCHIVE_BYTES, MAX_ARCHIVE_BYTES)
max_files = bounded_limit("RESTORE_MAX_FILES", MAX_FILES, MAX_FILES)
max_single_bytes = bounded_limit("RESTORE_MAX_SINGLE_BYTES", MAX_SINGLE_BYTES, MAX_SINGLE_BYTES)
max_total_bytes = bounded_limit("RESTORE_MAX_TOTAL_BYTES", MAX_TOTAL_BYTES, MAX_TOTAL_BYTES)
if archive.stat().st_size > max_archive_bytes:
    raise SystemExit(f"backup archive exceeds size limit: {archive.stat().st_size} > {max_archive_bytes}")

docker_roots = {
    "docker-data": Path(os.environ["DNSGUARD_DATA_DIR"]).expanduser().resolve(),
    "secrets": Path(os.environ["DNSGUARD_SECRET_DIR"]).expanduser().resolve(),
    "tls": Path(os.environ["DNSGUARD_TLS_DIR"]).expanduser().resolve(),
}


def relative_path(raw):
    path = Path(raw)
    if not raw or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise SystemExit(f"unsafe archive path: {raw!r}")
    return path


def assert_no_symlink_components(path, label):
    current = Path(path.anchor or "/")
    for part in Path(path).parts[1:]:
        current = current / part
        if current.is_symlink():
            raise SystemExit(f"{label} contains a symlink component: {current}")


def is_sensitive(relative):
    return relative == Path("config/dnsguard.env") or relative.parts[0] in {"secrets", "tls"}


def destination_for(relative):
    if relative == Path("config/dnsguard.env"):
        raw_destination = Path(os.environ["DNSGUARD_ENV_FILE"]).expanduser()
        if raw_destination.is_symlink():
            raise SystemExit(f"DNSGUARD_ENV_FILE is a symlink: {raw_destination}")
        assert_no_symlink_components(raw_destination.parent, "DNSGUARD_ENV_FILE")
        destination = raw_destination.resolve()
        return destination, True
    if not relative.parts or relative.parts[0] not in docker_roots:
        raise SystemExit(f"invalid Docker backup path: {relative}")
    sensitive = is_sensitive(relative)
    if sensitive and not restore_sensitive:
        raise SystemExit(f"sensitive entry requires RESTORE_INCLUDE_SENSITIVE=true: {relative}")
    root_dir = docker_roots[relative.parts[0]]
    assert_no_symlink_components(root_dir, str(relative.parts[0]))
    raw_destination = root_dir.joinpath(*relative.parts[1:])
    if raw_destination.is_symlink():
        raise SystemExit(f"restore destination is a symlink: {raw_destination}")
    destination = raw_destination.resolve()
    if destination != root_dir and root_dir not in destination.parents:
        raise SystemExit(f"path escapes Docker restore root: {relative}")
    assert_no_symlink_components(destination.parent, str(relative))
    return destination, sensitive


def safe_mode(relative, archive_mode):
    if relative == Path("config/dnsguard.env") or relative.parts[0] == "secrets":
        return 0o600
    if relative.parts[0] == "tls":
        return 0o644 if relative.name in {"fullchain.pem", "cert.pem", "certificate.pem"} else 0o600
    mode_bits = archive_mode & 0o660
    return mode_bits or 0o640


def owner_for(relative):
    if mode != "docker":
        return None
    if relative.parts[0] in {"docker-data", "secrets"}:
        return (10001, 10001)
    if relative.parts[0] == "tls":
        return (101, 101)
    return None


def fsync_file(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


restore_marker = docker_roots["docker-data"] / ".restore-in-progress.json"
assert_no_symlink_components(docker_roots["docker-data"], "docker-data")
if restore_marker.is_symlink() or restore_marker.exists():
    raise SystemExit(f"an incomplete restore marker exists; inspect it before retrying: {restore_marker}")

with tarfile.open(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    if len(members) != len({member.name for member in members}):
        raise SystemExit("backup archive contains duplicate members")
    if len(members) > max_files + 1:
        raise SystemExit(f"backup archive contains too many members: {len(members)}")
    total_size = 0
    members_by_name = {}
    for member in members:
        relative_member = relative_path(member.name)
        if not member.isfile() or relative_member == Path("."):
            raise SystemExit(f"unsafe backup member: {member.name}")
        if member.size < 0 or member.size > max_single_bytes:
            raise SystemExit(f"backup member exceeds size limit: {member.name}")
        total_size += member.size
        if total_size > max_total_bytes:
            raise SystemExit("backup archive extracted size exceeds limit")
        members_by_name[member.name] = member
    try:
        manifest_member = members_by_name["manifest.json"]
        manifest = json.loads(bundle.extractfile(manifest_member).read())
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid backup manifest: {exc}")
    if type(manifest.get("format")) is not int or manifest.get("format") not in (1, 2):
        raise SystemExit("unsupported backup format")
    if manifest.get("mode") != mode:
        raise SystemExit(f"backup mode mismatch: archive={manifest.get('mode')} requested={mode}")
    entries = manifest.get("files")
    if not isinstance(entries, list) or len(entries) > max_files:
        raise SystemExit("invalid or oversized backup manifest")
    manifest_names = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not isinstance(entry.get("sha256"), str):
            raise SystemExit("invalid backup manifest entry")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", entry["sha256"]):
            raise SystemExit(f"invalid checksum in backup manifest: {entry['path']}")
        relative = relative_path(entry["path"])
        if relative == Path("manifest.json") or str(relative) in manifest_names:
            raise SystemExit(f"duplicate manifest path: {relative}")
        manifest_names.append(str(relative))
        actual_sensitive = is_sensitive(relative)
        if "sensitive" in entry and type(entry["sensitive"]) is not bool:
            raise SystemExit(f"invalid sensitivity marker: {relative}")
        if "sensitive" in entry and entry["sensitive"] != actual_sensitive:
            raise SystemExit(f"manifest sensitivity does not match protected path: {relative}")
        if str(relative) not in members_by_name:
            raise SystemExit(f"manifest member missing: {relative}")
    expected_members = set(manifest_names) | {"manifest.json"}
    if set(members_by_name) != expected_members:
        extras = sorted(set(members_by_name) - expected_members)
        missing = sorted(expected_members - set(members_by_name))
        raise SystemExit(f"archive and manifest members differ; extras={extras}, missing={missing}")

    with tempfile.TemporaryDirectory(prefix="dnsguard-restore-") as temp:
        stage = Path(temp) / "stage"
        rollback = Path(temp) / "rollback"
        stage.mkdir()
        rollback.mkdir()
        planned = []
        for entry in entries:
            relative = relative_path(entry["path"])
            destination, sensitive = destination_for(relative)
            if sensitive and not restore_sensitive:
                raise SystemExit(f"sensitive entry requires explicit opt-in: {relative}")
            source = stage / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            member = members_by_name[str(relative)]
            extracted = bundle.extractfile(member)
            data = extracted.read(max_single_bytes + 1)
            if len(data) != member.size or len(data) > max_single_bytes:
                raise SystemExit(f"backup member read size mismatch: {relative}")
            source.write_bytes(data)
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise SystemExit(f"checksum mismatch: {relative}")
            planned.append((source, destination, safe_mode(relative, member.mode), owner_for(relative), relative))

        existing = []
        for _, destination, _, _, relative in planned:
            if destination.exists() or destination.is_symlink():
                if destination.is_symlink() or not destination.is_file():
                    raise SystemExit(f"restore destination is not a regular file: {destination}")
                existing.append((destination, relative))
        if existing and not allow_overwrite:
            names = ", ".join(str(relative) for _, relative in existing[:5])
            raise SystemExit(f"restore would overwrite existing files ({names}); set RESTORE_ALLOW_OVERWRITE=true for an opt-in restore")
        if not allow_overwrite:
            for _, destination, _, _, _ in planned:
                if destination.exists() or destination.is_symlink():
                    raise SystemExit(f"restore destination appeared during validation: {destination}")

        backups = {}
        original_metadata = {}
        applied = []
        temporary_files = []
        marker_created = False
        try:
            docker_roots["docker-data"].mkdir(parents=True, exist_ok=True, mode=0o750)
            marker_fd = os.open(restore_marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            try:
                marker_payload = json.dumps({"archive": str(archive), "pid": os.getpid(), "status": "in_progress"}, separators=(",", ":")) + "\n"
                marker_bytes = marker_payload.encode()
                while marker_bytes:
                    marker_bytes = marker_bytes[os.write(marker_fd, marker_bytes):]
                os.fsync(marker_fd)
            finally:
                os.close(marker_fd)
            marker_created = True
            fsync_directory(restore_marker.parent)
            for index, (source, destination, mode_bits, owner, relative) in enumerate(planned):
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
                if destination.exists():
                    backup = rollback / str(index)
                    metadata = destination.stat()
                    shutil.copy2(destination, backup)
                    os.chmod(backup, metadata.st_mode & 0o7777)
                    if os.geteuid() == 0:
                        os.chown(backup, metadata.st_uid, metadata.st_gid)
                    backups[destination] = backup
                    original_metadata[destination] = metadata
                temporary = destination.with_name(f".{destination.name}.restore.tmp.{os.getpid()}")
                temporary_files.append(temporary)
                shutil.copy2(source, temporary)
                os.chmod(temporary, mode_bits)
                if owner is not None and os.geteuid() == 0:
                    os.chown(temporary, *owner)
                fsync_file(temporary)
                os.replace(temporary, destination)
                fsync_directory(destination.parent)
                applied.append(destination)
            restore_marker.unlink()
            marker_created = False
            fsync_directory(restore_marker.parent)
        except Exception as exc:
            rollback_errors = []
            for destination in reversed(applied):
                backup = backups.get(destination)
                if backup is not None:
                    try:
                        os.replace(backup, destination)
                        metadata = original_metadata[destination]
                        os.chmod(destination, metadata.st_mode & 0o7777)
                        if os.geteuid() == 0:
                            os.chown(destination, metadata.st_uid, metadata.st_gid)
                        fsync_directory(destination.parent)
                    except Exception as rollback_error:
                        rollback_errors.append(f"{destination}: {rollback_error}")
                else:
                    try:
                        destination.unlink()
                        fsync_directory(destination.parent)
                    except FileNotFoundError:
                        pass
                    except Exception as rollback_error:
                        rollback_errors.append(f"{destination}: {rollback_error}")
            for temporary in temporary_files:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            if marker_created and not rollback_errors:
                try:
                    restore_marker.unlink()
                    marker_created = False
                    fsync_directory(restore_marker.parent)
                except Exception as marker_error:
                    rollback_errors.append(f"restore marker: {marker_error}")
            if rollback_errors:
                raise SystemExit(f"restore failed; rollback is incomplete and the restore marker was retained: {exc}; rollback errors={rollback_errors}")
            raise SystemExit(f"restore failed and previous files were restored: {exc}")
        for _, destination, _, _, relative in planned:
            print(f"restored {relative} -> {destination}")
PY
