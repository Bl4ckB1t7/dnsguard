#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for name in primary secondary secondary-2; do
  pid_file="$ROOT/dev/bind-rpz/run/$name.pid"
  if [[ -f "$pid_file" ]]; then
    pid="$(cat "$pid_file")"
    kill "$pid" 2>/dev/null || true
    rm -f "$pid_file"
  fi
done
pkill -TERM -f 'named .* -c /etc/bind/dnsguard-dev-rpz/' 2>/dev/null || true
echo "BIND RPZ development environment stopped"
