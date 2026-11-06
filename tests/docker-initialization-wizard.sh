#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIND_DIR="$ROOT_DIR/tests/docker-production-bind"
BIND_RUNTIME="$BIND_DIR/runtime"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
BIND_NETWORK_NAME="${BIND_NETWORK_NAME:-dnsguard-init-bind-$RUN_ID}"
DNSGUARD_INTERNAL_NETWORK_NAME="${DNSGUARD_INTERNAL_NETWORK_NAME:-dnsguard-init-internal-$RUN_ID}"
DNSGUARD_INTERNAL_SUBNET="${DNSGUARD_INTERNAL_SUBNET:-172.30.1.0/24}"
BIND_PRIMARY_CONTAINER="${BIND_PRIMARY_CONTAINER:-dnsguard-init-bind-primary-$RUN_ID}"
BIND_SECONDARY_1_CONTAINER="${BIND_SECONDARY_1_CONTAINER:-dnsguard-init-bind-secondary-1-$RUN_ID}"
BIND_SECONDARY_2_CONTAINER="${BIND_SECONDARY_2_CONTAINER:-dnsguard-init-bind-secondary-2-$RUN_ID}"
BIND_PRIMARY_HOST_PORT="${BIND_PRIMARY_HOST_PORT:-17453}"
BIND_SECONDARY_1_HOST_PORT="${BIND_SECONDARY_1_HOST_PORT:-17454}"
BIND_SECONDARY_2_HOST_PORT="${BIND_SECONDARY_2_HOST_PORT:-17455}"
export BIND_NETWORK_NAME DNSGUARD_INTERNAL_NETWORK_NAME DNSGUARD_INTERNAL_SUBNET BIND_PRIMARY_CONTAINER BIND_SECONDARY_1_CONTAINER BIND_SECONDARY_2_CONTAINER
export BIND_PRIMARY_HOST_PORT BIND_SECONDARY_1_HOST_PORT BIND_SECONDARY_2_HOST_PORT
BIND_PROJECT="dnsguard-init-bind"
PROJECT="dnsguard-init-wizard"
RUNTIME="$ROOT_DIR/tests/docker-initialization-runtime"
DATA_DIR="$RUNTIME/data"
SECRET_DIR="$RUNTIME/secrets"
TLS_DIR="$RUNTIME/tls"
ENV_FILE="$RUNTIME/dnsguard.env"
REPORT="$RUNTIME/acceptance-report.md"
WEB_HOST_PORT="${DNSGUARD_WEB_PORT:-19444}"
BASE_URL="https://127.0.0.1:$WEB_HOST_PORT"
COMPOSE=(docker compose -p "$PROJECT" -f "$ROOT_DIR/compose.yaml" -f "$ROOT_DIR/tests/docker-production-bind-net.yaml")
BIND_COMPOSE=(docker compose -p "$BIND_PROJECT" -f "$BIND_DIR/compose.yaml")
declare -a NAMES=() STATUS=() EVIDENCE=()

record() { NAMES+=("$1"); STATUS+=("$2"); EVIDENCE+=("$3"); printf '%-10s %s\n' "$2" "$1"; }
compose() { "${COMPOSE[@]}" "$@"; }
bind_compose() { "${BIND_COMPOSE[@]}" "$@"; }

run_case() {
  local name="$1" fn="$2" file="$RUNTIME/evidence/${#NAMES[@]}-$1.log" code
  mkdir -p "$RUNTIME/evidence"
  set +e; (set -e; "$fn") >"$file" 2>&1; code=$?; set -e
  if ((code == 0)); then record "$name" PASS "$file"; else record "$name" FAIL "$file"; fi
}

prepare() {
  compose down --remove-orphans >/dev/null 2>&1 || true
  bind_compose down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$RUNTIME" "$BIND_RUNTIME"
  mkdir -p "$BIND_RUNTIME/keys" "$BIND_RUNTIME/primary-data" "$BIND_RUNTIME/primary-logs" \
    "$BIND_RUNTIME/secondary-1-data" "$BIND_RUNTIME/secondary-1-logs" "$BIND_RUNTIME/secondary-2-data" "$BIND_RUNTIME/secondary-2-logs"
  local secret; secret="$(openssl rand -base64 32 | tr -d '\n')"
  printf 'key "rpz-manager" { algorithm hmac-sha256; secret "%s"; };\n' "$secret" >"$BIND_RUNTIME/keys/rpz-manager.key"
  chmod 0640 "$BIND_RUNTIME/keys/rpz-manager.key"; chown 53:53 "$BIND_RUNTIME/keys/rpz-manager.key"
  cat >"$BIND_RUNTIME/primary-data/rpz.local.zone" <<'EOF'
$TTL 60
$ORIGIN rpz.local.
@ IN SOA localhost. hostmaster.localhost. (1 1h 15m 30d 60)
  IN NS localhost.
EOF
  cp "$BIND_RUNTIME/primary-data/rpz.local.zone" "$BIND_RUNTIME/secondary-1-data/rpz.local.zone"
  cp "$BIND_RUNTIME/primary-data/rpz.local.zone" "$BIND_RUNTIME/secondary-2-data/rpz.local.zone"
  chmod -R 0775 "$BIND_RUNTIME"/*-data "$BIND_RUNTIME"/*-logs
  chown -R 53:53 "$BIND_RUNTIME"/*-data "$BIND_RUNTIME"/*-logs
  bind_compose up -d >/dev/null
  for _ in $(seq 1 60); do docker exec "$BIND_PRIMARY_CONTAINER" dig +tcp +time=1 +tries=1 @127.0.0.1 rpz.local SOA +short 2>/dev/null | grep -q '[0-9]' && break; sleep .5; done
  docker exec "$BIND_PRIMARY_CONTAINER" dig +tcp +time=2 +tries=1 @127.0.0.1 rpz.local SOA +short >/dev/null
  mkdir -p "$DATA_DIR/rpz" "$SECRET_DIR" "$TLS_DIR"
  cp "$BIND_RUNTIME/keys/rpz-manager.key" "$SECRET_DIR/rpz-manager.key"; chown 10001:10001 "$SECRET_DIR/rpz-manager.key"; chmod 0640 "$SECRET_DIR/rpz-manager.key"
  printf '%s\n' 'setup-bootstrap-token-012345678901234567890' >"$SECRET_DIR/bootstrap.token"; chown 10001:10001 "$SECRET_DIR/bootstrap.token"; chmod 0600 "$SECRET_DIR/bootstrap.token"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$TLS_DIR/privkey.pem" -out "$TLS_DIR/fullchain.pem" -subj '/CN=localhost' >/dev/null 2>&1
  chmod 0644 "$TLS_DIR/fullchain.pem"; chown 101:101 "$TLS_DIR/privkey.pem"; chmod 0640 "$TLS_DIR/privkey.pem"
  cat >"$ENV_FILE" <<EOF
APP_ENV=production
AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_SECRET=$(openssl rand -hex 32)
MONITORING_TOKEN=$(openssl rand -hex 32)
AUTH_FILE=/var/lib/dnsguard/auth.json
DNS_NODE_CONFIG_FILE=/var/lib/dnsguard/dns-nodes.json
INITIALIZATION_FILE=/var/lib/dnsguard/initialization.json
BOOTSTRAP_TOKEN_FILE=/run/dnsguard-secrets/bootstrap.token
BOOTSTRAP_KEY_DIR=/run/dnsguard-secrets
DNS_NODE_ALLOWED_CIDRS=172.32.0.0/24
RPZ_ZONE=rpz.local
RPZ_PUBLISH_MODE=nsupdate
RPZ_PRIMARY=172.32.0.10
RPZ_PRIMARY_PORT=53
RPZ_KEY_FILE=/run/dnsguard-secrets/rpz-manager.key
RPZ_ARTIFACT_FILE=/var/lib/dnsguard/rpz/rpz.local.db
RPZ_PUBLISH_JOBS_FILE=/var/lib/dnsguard/publish-jobs.json
DNS_STATE_FILE=/var/lib/dnsguard/dns-state.json
AUDIT_FILE=/var/lib/dnsguard/audit.json
TRUST_PROXY_TLS=true
TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=172.28.0.0/24
LISTEN_ADDR=0.0.0.0:8080
EOF
  chmod 0640 "$ENV_FILE"; chown -R 10001:10001 "$DATA_DIR" "$SECRET_DIR"; chmod 0750 "$DATA_DIR" "$SECRET_DIR"
}

start() {
  export DNSGUARD_ENV_FILE="$ENV_FILE" DNSGUARD_DATA_DIR="$DATA_DIR" DNSGUARD_SECRET_DIR="$SECRET_DIR" DNSGUARD_TLS_DIR="$TLS_DIR" DNSGUARD_WEB_PORT="$WEB_HOST_PORT" DNSGUARD_WEB_BIND_IP=127.0.0.1
  export DNSGUARD_API_IMAGE=dnsguard-api:1.0.0 DNSGUARD_WEB_IMAGE=dnsguard-web:1.0.0
  if [[ "${SKIP_BUILD:-false}" != true ]]; then
    compose build >/dev/null
  fi
  compose up -d >/dev/null
  for _ in $(seq 1 60); do curl -kfsS "$BASE_URL/api/health" >/dev/null 2>&1 && return; sleep 1; done
  compose logs --no-color; return 1
}

case_bad_token() {
  local code publish_code
  code="$(curl -ksS -o "$RUNTIME/bad-response" -w '%{http_code}' -X POST "$BASE_URL/api/setup/validate" -H 'Content-Type: application/json' -H 'X-DNSGuard-Bootstrap: wrong-token' -d '{}')"
  publish_code="$(curl -ksS -o "$RUNTIME/uninitialized-publish" -w '%{http_code}' -X POST "$BASE_URL/api/dns/rpz/publish" -H 'Content-Type: application/json' -d '{}')"
  [[ "$code" == 401 && "$publish_code" == 428 ]] && ! grep -q 'setup-bootstrap-token' "$RUNTIME/bad-response" && ! compose logs --no-color 2>/dev/null | grep -q 'setup-bootstrap-token'
}

payload() {
  cat <<EOF
{"username":"admin","password":"a-strong-setup-password","zone":"rpz.local","primary":{"name":"bind-primary","role":"primary","address":"172.32.0.10:53"},"secondaries":[{"name":"bind-secondary-1","role":"secondary","address":"172.32.0.11:53"},{"name":"bind-secondary-2","role":"secondary","address":"172.32.0.12:53"}],"tsigKeyPath":"/run/dnsguard-secrets/rpz-manager.key","writeTest":true}
EOF
}

case_first_and_concurrent() {
  local one="$RUNTIME/one" two="$RUNTIME/two" c1 c2
  (curl -ksS -o "$one" -w '%{http_code}' -X POST "$BASE_URL/api/setup/complete" -H 'Content-Type: application/json' -H 'X-DNSGuard-Bootstrap: setup-bootstrap-token-012345678901234567890' --data-binary "$(payload)") >"$one.code" &
  (curl -ksS -o "$two" -w '%{http_code}' -X POST "$BASE_URL/api/setup/complete" -H 'Content-Type: application/json' -H 'X-DNSGuard-Bootstrap: setup-bootstrap-token-012345678901234567890' --data-binary "$(payload)") >"$two.code" &
  wait
  c1="$(cat "$one.code")"; c2="$(cat "$two.code")"
  { [[ "$c1" == 200 && "$c2" == 409 ]] || [[ "$c1" == 409 && "$c2" == 200 ]]; }
  grep -q 'initialized' "$one" "$two"
}

case_gate_and_recreate() {
  local status
  status="$(curl -ksS "$BASE_URL/api/setup/status")"
  grep -q '"initialized":true' <<<"$status"
  curl -ksS -o "$RUNTIME/repeat" -w '%{http_code}' -X POST "$BASE_URL/api/setup/complete" -H 'Content-Type: application/json' -H 'X-DNSGuard-Bootstrap: setup-bootstrap-token-012345678901234567890' --data-binary "$(payload)" | grep -q '^409$'
  compose down >/dev/null
  compose up -d >/dev/null
  for _ in $(seq 1 45); do curl -kfsS "$BASE_URL/api/health" >/dev/null 2>&1 && break; sleep 1; done
  grep -q '"initialized":true' <(curl -ksS "$BASE_URL/api/setup/status")
  grep -Eq '"status"[[:space:]]*:[[:space:]]*"completed"' "$DATA_DIR/initialization.json"
  [[ -f "$DATA_DIR/auth.json" && -f "$DATA_DIR/dns-nodes.json" ]]
}

write_report() {
  mkdir -p "$RUNTIME"
  { echo '# DNSGuard Web 首次初始化向导 Docker 验收报告'; echo; echo '- 隔离 BIND：tests/docker-production-bind，172.32.0.0/24'; echo '- 生产连接：无'; echo; echo '| 用例 | 结果 | 证据 |'; echo '|---|---|---|'; for i in "${!NAMES[@]}"; do echo "| ${NAMES[$i]} | ${STATUS[$i]} | \`${EVIDENCE[$i]}\` |"; done; } >"$REPORT"
}

cleanup() {
  local code=$?; mkdir -p "$RUNTIME"; compose logs --no-color >"$RUNTIME/compose.log" 2>&1 || true; compose down --remove-orphans >/dev/null 2>&1 || true; bind_compose logs --no-color >"$RUNTIME/bind-compose.log" 2>&1 || true; bind_compose down --remove-orphans >/dev/null 2>&1 || true; write_report || true; return "$code"
}

main() {
  if ! command -v docker >/dev/null 2>&1; then
    echo 'NOT RUN: Docker CLI unavailable' >&2
    exit 2
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo 'NOT RUN: curl unavailable' >&2
    exit 2
  fi
  if ! docker info >/dev/null 2>&1; then
    echo 'NOT RUN: Docker Engine unavailable or inaccessible' >&2
    exit 2
  fi
  trap cleanup EXIT
  prepare; start
  run_case 'bad-bootstrap-token-is-rejected' case_bad_token
  run_case 'first-initialization-and-concurrent-takeover' case_first_and_concurrent
  run_case 'marker-publish-gate-and-container-recreate' case_gate_and_recreate
  write_report
  ! printf '%s\n' "${STATUS[@]}" | grep -q '^FAIL$'
}
main "$@"
