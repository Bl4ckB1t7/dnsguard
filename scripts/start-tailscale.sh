#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IP="$(tailscale ip -4 | head -n 1)"
RUN_DIR="$ROOT/.run"
DATA_DIR="$ROOT/data"
RPZ_PUBLISH_MODE="${RPZ_PUBLISH_MODE:-artifact}"
RPZ_PRIMARY="${RPZ_PRIMARY:-RPZ_PRIMARY}"
RPZ_PRIMARY_PORT="${RPZ_PRIMARY_PORT:-53}"
RPZ_ZONE="${RPZ_ZONE:-rpz.local}"
RPZ_KEY_FILE="${RPZ_KEY_FILE:-}"
AUTH_ENABLED="${AUTH_ENABLED:-false}"
DNS_NODE_ADDRESSES="${DNS_NODE_ADDRESSES:-}"
RPZ_LOG_FILES="${RPZ_LOG_FILES:-}"
RPZ_HIT_DEDUP_SECONDS="${RPZ_HIT_DEDUP_SECONDS:-2}"
APP_ENV="${APP_ENV:-development}"
TLS_CERT_FILE="${TLS_CERT_FILE:-}"
TLS_KEY_FILE="${TLS_KEY_FILE:-}"
TRUST_PROXY_TLS="${TRUST_PROXY_TLS:-false}"

if [[ -z "$IP" ]]; then
  echo "No Tailscale IPv4 address found" >&2
  exit 1
fi

mkdir -p "$RUN_DIR" "$DATA_DIR"

if [[ -f "$RUN_DIR/api.pid" ]] && kill -0 "$(cat "$RUN_DIR/api.pid")" 2>/dev/null; then
  echo "DNS API already running: $(cat "$RUN_DIR/api.pid")"
else
  (cd "$ROOT/server" && go build -o "$RUN_DIR/dns-ops-api" .)
  setsid env APP_ENV="$APP_ENV" LISTEN_ADDR=127.0.0.1:8080 DNS_STATE_FILE="$DATA_DIR/dns-state.json" AUDIT_FILE="$DATA_DIR/audit.json" RPZ_ARTIFACT_FILE="$DATA_DIR/rpz/$RPZ_ZONE.db" RPZ_PUBLISH_MODE="$RPZ_PUBLISH_MODE" RPZ_PRIMARY="$RPZ_PRIMARY" RPZ_PRIMARY_PORT="$RPZ_PRIMARY_PORT" RPZ_ZONE="$RPZ_ZONE" RPZ_KEY_FILE="$RPZ_KEY_FILE" RPZ_LOG_FILES="$RPZ_LOG_FILES" RPZ_HIT_DEDUP_SECONDS="$RPZ_HIT_DEDUP_SECONDS" AUTH_ENABLED="$AUTH_ENABLED" TLS_CERT_FILE="$TLS_CERT_FILE" TLS_KEY_FILE="$TLS_KEY_FILE" TRUST_PROXY_TLS="$TRUST_PROXY_TLS" DNS_NODE_ADDRESSES="$DNS_NODE_ADDRESSES" "$RUN_DIR/dns-ops-api" >"$RUN_DIR/api.log" 2>&1 < /dev/null &
  echo $! >"$RUN_DIR/api.pid"
fi

if [[ -f "$RUN_DIR/web.pid" ]] && kill -0 "$(cat "$RUN_DIR/web.pid")" 2>/dev/null; then
  echo "DNS Web already running: $(cat "$RUN_DIR/web.pid")"
else
  cd "$ROOT"
  setsid "$ROOT/node_modules/.bin/vite" --host "$IP" --port 5173 --strictPort >"$RUN_DIR/web.log" 2>&1 < /dev/null &
  echo $! >"$RUN_DIR/web.pid"
fi

echo "DNS Ops Platform: http://$IP:5173"
echo "API is proxied through the frontend and stays on 127.0.0.1:8080"
