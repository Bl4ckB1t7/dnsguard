#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stop_process() {
  local name="$1"
  local pid_file="$ROOT/.run/$name.pid"
  [[ -f "$pid_file" ]] || return 0

  local pid command group_commands pgid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ ! "$pid" =~ ^[0-9]+$ ]] || ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$pid_file"
    return 0
  fi

  pgid="$(ps -p "$pid" -o pgid= 2>/dev/null | tr -d ' ')"
  command="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  group_commands="$(ps -eo pgid=,args= 2>/dev/null | awk -v group="$pgid" '$1 == group { $1=""; sub(/^ /, ""); print }')"
  if [[ "$command" != *"$ROOT"* && "$group_commands" != *"$ROOT"* ]]; then
    echo "Ignoring stale $name PID $pid"
    rm -f "$pid_file"
    return 0
  fi

  if [[ "$pgid" == "$pid" ]]; then
    kill -TERM -- "-$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      ps -eo pgid= 2>/dev/null | awk -v group="$pid" '$1 == group { found=1 } END { exit found ? 0 : 1 }' || break
      sleep 0.1
    done
    if ps -eo pgid= 2>/dev/null | awk -v group="$pid" '$1 == group { found=1 } END { exit found ? 0 : 1 }'; then
      kill -KILL -- "-$pid" 2>/dev/null || true
    fi
  else
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$pid_file"
}

for name in api web; do
  stop_process "$name"
done
echo "DNS Ops Platform stopped"
