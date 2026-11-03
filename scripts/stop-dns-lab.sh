#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for name in primary secondary; do
  pid_file="$ROOT/dns-lab/run/$name.pid"
  if [[ -f "$pid_file" ]]; then
    pid="$(cat "$pid_file")"
    kill "$pid" 2>/dev/null || true
    rm -f "$pid_file"
  fi
done
pkill -TERM -f 'named -u kali -c /etc/bind/dns-ops-lab/' 2>/dev/null || true
echo "BIND lab stopped"
