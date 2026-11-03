#!/usr/bin/env bash
set -euo pipefail

MONITORING_URL="${MONITORING_URL:-http://127.0.0.1:8080/api/monitoring/status}"
MONITORING_TOKEN="${MONITORING_TOKEN:-}"

for command_name in curl python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    exit 2
  fi
done

headers=()
if [[ -n "$MONITORING_TOKEN" ]]; then
  headers=(-H "Authorization: Bearer $MONITORING_TOKEN")
fi
response="$(curl --fail-with-body -sS --max-time 10 "${headers[@]}" "$MONITORING_URL")"
printf '%s\n' "$response"
printf '%s' "$response" | python3 -c '
import json, sys
payload = json.load(sys.stdin)
status = payload.get("status")
if status != "ok":
    print(f"ALERT: DNS Ops status is {status!r}", file=sys.stderr)
    raise SystemExit(1)
'
