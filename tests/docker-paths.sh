#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/docker-paths.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dnsguard-paths.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

DNSGUARD_DATA_DIR="./tests/path-fixture/data"
DNSGUARD_SECRET_DIR="./tests/path-fixture/secrets"
DNSGUARD_TLS_DIR="./tests/path-fixture/tls"
DNSGUARD_BIND_LOG_DIR="./tests/path-fixture/logs"
dnsguard_prepare_paths "$ROOT"
[[ "$DNSGUARD_DATA_DIR" == "$ROOT/tests/path-fixture/data" ]]
[[ "$DNSGUARD_SECRET_DIR" == "$ROOT/tests/path-fixture/secrets" ]]

DNSGUARD_DATA_DIR="$WORK/data"
DNSGUARD_SECRET_DIR="$WORK/secrets"
DNSGUARD_TLS_DIR="$WORK/tls"
DNSGUARD_BIND_LOG_DIR="$WORK/logs"
dnsguard_prepare_paths "$ROOT"
[[ "$DNSGUARD_DATA_DIR" == "$WORK/data" ]]

mkdir -p "$WORK/dir with spaces"
(
  cd /tmp
  DNSGUARD_DATA_DIR="$WORK/dir with spaces/data"
  DNSGUARD_SECRET_DIR="$WORK/dir with spaces/secrets"
  DNSGUARD_TLS_DIR="$WORK/dir with spaces/tls"
  DNSGUARD_BIND_LOG_DIR="$WORK/dir with spaces/logs"
  dnsguard_prepare_paths "$ROOT"
  [[ "$DNSGUARD_DATA_DIR" == "$WORK/dir with spaces/data" ]]
)

if DNSGUARD_DATA_DIR="$WORK/shared" DNSGUARD_SECRET_DIR="$WORK/shared/secrets" DNSGUARD_TLS_DIR="$WORK/tls" DNSGUARD_BIND_LOG_DIR="$WORK/logs" dnsguard_prepare_paths "$ROOT"; then
  echo 'overlapping Docker directories accepted' >&2
  exit 1
fi

if DNSGUARD_DATA_DIR=/ DNSGUARD_SECRET_DIR="$WORK/secrets" DNSGUARD_TLS_DIR="$WORK/tls" DNSGUARD_BIND_LOG_DIR="$WORK/logs" dnsguard_prepare_paths "$ROOT"; then
  echo 'dangerous root data directory accepted' >&2
  exit 1
fi

mkdir -p "$WORK/real"
ln -s "$WORK/real" "$WORK/symlink"
if DNSGUARD_DATA_DIR="$WORK/symlink/data" DNSGUARD_SECRET_DIR="$WORK/secrets" DNSGUARD_TLS_DIR="$WORK/tls" DNSGUARD_BIND_LOG_DIR="$WORK/logs" dnsguard_prepare_paths "$ROOT"; then
  echo 'symlinked data directory accepted' >&2
  exit 1
fi

echo 'PASS: default, absolute, relative, spaces, overlap, missing, dangerous-path and symlink Docker path checks'
