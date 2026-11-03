#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

for command_name in ip npm go dig; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    exit 1
  fi
done

BIND_INTERFACE="${BIND_INTERFACE:-tailscale0}"
WEB_BIND_ADDRESS="${WEB_BIND_ADDRESS:-}"
if [[ -z "$WEB_BIND_ADDRESS" ]]; then
  WEB_BIND_ADDRESS="$(ip -4 -o addr show dev "$BIND_INTERFACE" 2>/dev/null | awk '{split($4, address, "/"); print address[1]; exit}')"
fi
RUN_DIR="$ROOT/.run"
DATA_DIR="$ROOT/data"
RPZ_PUBLISH_MODE="${RPZ_PUBLISH_MODE:-artifact}"
RPZ_PRIMARY="${RPZ_PRIMARY:-RPZ_PRIMARY}"
RPZ_PRIMARY_PORT="${RPZ_PRIMARY_PORT:-53}"
RPZ_ZONE="${RPZ_ZONE:-rpz.local}"
RPZ_KEY_FILE="${RPZ_KEY_FILE:-}"
AUTH_ENABLED="${AUTH_ENABLED:-true}"
AUTH_USERNAME="${AUTH_USERNAME:-admin}"
AUTH_SECRET="${AUTH_SECRET:-}"
AUTH_FILE="${AUTH_FILE:-$ROOT/.run/auth.json}"
TRUST_PROXY_HEADERS="${TRUST_PROXY_HEADERS:-false}"
DNS_NODE_ADDRESSES="${DNS_NODE_ADDRESSES:-}"
DNS_NODE_CONFIG_FILE="${DNS_NODE_CONFIG_FILE:-$ROOT/config/dns-nodes.json}"
DNS_NODE_ALLOWED_CIDRS="${DNS_NODE_ALLOWED_CIDRS:-127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7}"
DNS_NODE_ALLOWED_HOSTS="${DNS_NODE_ALLOWED_HOSTS:-}"
RPZ_LOG_FILES="${RPZ_LOG_FILES:-}"
RPZ_HIT_DEDUP_SECONDS="${RPZ_HIT_DEDUP_SECONDS:-2}"
RPZ_PUBLISH_TIMEOUT_SECONDS="${RPZ_PUBLISH_TIMEOUT_SECONDS:-15}"
RPZ_PUBLISH_RETRIES="${RPZ_PUBLISH_RETRIES:-2}"
RPZ_PUBLISH_RETRY_BACKOFF_SECONDS="${RPZ_PUBLISH_RETRY_BACKOFF_SECONDS:-1}"
DNS_HEALTH_CACHE_SECONDS="${DNS_HEALTH_CACHE_SECONDS:-5}"
DNS_HEALTH_INTERVAL_SECONDS="${DNS_HEALTH_INTERVAL_SECONDS:-10}"
APP_ENV="${APP_ENV:-development}"
TLS_CERT_FILE="${TLS_CERT_FILE:-}"
TLS_KEY_FILE="${TLS_KEY_FILE:-}"
TRUST_PROXY_TLS="${TRUST_PROXY_TLS:-false}"
MONITORING_TOKEN="${MONITORING_TOKEN:-}"
BUILD_ON_START="${BUILD_ON_START:-true}"
WEB_MODE="${WEB_MODE:-preview}"

if [[ -z "$WEB_BIND_ADDRESS" ]]; then
  echo "No IPv4 address found on interface $BIND_INTERFACE; set BIND_INTERFACE or WEB_BIND_ADDRESS" >&2
  exit 1
fi

mkdir -p "$RUN_DIR" "$DATA_DIR"

if [[ "$BUILD_ON_START" == "true" ]]; then
  if [[ ! -d "$ROOT/node_modules" ]]; then
    npm ci
  fi
  npm run build
fi

if [[ -f "$RUN_DIR/api.pid" ]] && kill -0 "$(cat "$RUN_DIR/api.pid")" 2>/dev/null; then
  echo "DNS API already running: $(cat "$RUN_DIR/api.pid")"
else
  (cd "$ROOT/server" && go build -o "$RUN_DIR/dns-ops-api" .)
  setsid env APP_ENV="$APP_ENV" LISTEN_ADDR=127.0.0.1:8080 DNS_STATE_FILE="$DATA_DIR/dns-state.json" DNS_NODE_CONFIG_FILE="$DNS_NODE_CONFIG_FILE" DNS_NODE_ALLOWED_CIDRS="$DNS_NODE_ALLOWED_CIDRS" DNS_NODE_ALLOWED_HOSTS="$DNS_NODE_ALLOWED_HOSTS" AUDIT_FILE="$DATA_DIR/audit.json" RPZ_ARTIFACT_FILE="$DATA_DIR/rpz/$RPZ_ZONE.db" RPZ_PUBLISH_MODE="$RPZ_PUBLISH_MODE" RPZ_PRIMARY="$RPZ_PRIMARY" RPZ_PRIMARY_PORT="$RPZ_PRIMARY_PORT" RPZ_ZONE="$RPZ_ZONE" RPZ_KEY_FILE="$RPZ_KEY_FILE" RPZ_LOG_FILES="$RPZ_LOG_FILES" RPZ_HIT_DEDUP_SECONDS="$RPZ_HIT_DEDUP_SECONDS" RPZ_PUBLISH_TIMEOUT_SECONDS="$RPZ_PUBLISH_TIMEOUT_SECONDS" RPZ_PUBLISH_RETRIES="$RPZ_PUBLISH_RETRIES" RPZ_PUBLISH_RETRY_BACKOFF_SECONDS="$RPZ_PUBLISH_RETRY_BACKOFF_SECONDS" DNS_HEALTH_CACHE_SECONDS="$DNS_HEALTH_CACHE_SECONDS" DNS_HEALTH_INTERVAL_SECONDS="$DNS_HEALTH_INTERVAL_SECONDS" AUTH_ENABLED="$AUTH_ENABLED" AUTH_USERNAME="$AUTH_USERNAME" AUTH_SECRET="$AUTH_SECRET" AUTH_FILE="$AUTH_FILE" TRUST_PROXY_HEADERS="$TRUST_PROXY_HEADERS" TLS_CERT_FILE="$TLS_CERT_FILE" TLS_KEY_FILE="$TLS_KEY_FILE" TRUST_PROXY_TLS="$TRUST_PROXY_TLS" MONITORING_TOKEN="$MONITORING_TOKEN" DNS_NODE_ADDRESSES="$DNS_NODE_ADDRESSES" "$RUN_DIR/dns-ops-api" >"$RUN_DIR/api.log" 2>&1 < /dev/null &
  echo $! >"$RUN_DIR/api.pid"
fi

if [[ -f "$RUN_DIR/web.pid" ]] && kill -0 "$(cat "$RUN_DIR/web.pid")" 2>/dev/null; then
  echo "DNS Web already running: $(cat "$RUN_DIR/web.pid")"
else
  cd "$ROOT"
  case "$WEB_MODE" in
    preview) web_command=(npm run preview -- --host "$WEB_BIND_ADDRESS" --port 5173 --strictPort) ;;
    dev) web_command=("$ROOT/node_modules/.bin/vite" --host "$WEB_BIND_ADDRESS" --port 5173 --strictPort) ;;
    *) echo "WEB_MODE must be preview or dev" >&2; exit 1 ;;
  esac
  setsid "${web_command[@]}" >"$RUN_DIR/web.log" 2>&1 < /dev/null &
  echo $! >"$RUN_DIR/web.pid"
fi

echo "DNS Ops Platform: http://$WEB_BIND_ADDRESS:5173"
echo "API is proxied through the frontend and stays on 127.0.0.1:8080"
echo "Web mode: $WEB_MODE"
