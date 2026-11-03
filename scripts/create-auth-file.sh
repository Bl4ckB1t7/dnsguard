#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTH_FILE="${AUTH_FILE:-/etc/dns-ops/auth.json}"
AUTH_USERNAME="${AUTH_USERNAME:-admin}"

if [[ ! -t 0 ]]; then
  echo "Run this command from an interactive terminal." >&2
  exit 1
fi

(cd "$ROOT/server" && go run ./cmd/authgen -output "$AUTH_FILE" -username "$AUTH_USERNAME")
