#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIND_DIR="$ROOT_DIR/tests/docker-production-bind"
BIND_RUNTIME="$BIND_DIR/runtime"
BIND_PROJECT="dnsguard-production-bind"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
BIND_NETWORK_NAME="${BIND_NETWORK_NAME:-dnsguard-prod-bind-$RUN_ID}"
DNSGUARD_INTERNAL_NETWORK_NAME="${DNSGUARD_INTERNAL_NETWORK_NAME:-dnsguard-prod-internal-$RUN_ID}"
DNSGUARD_INTERNAL_SUBNET="${DNSGUARD_INTERNAL_SUBNET:-172.30.0.0/24}"
BIND_PRIMARY_CONTAINER="${BIND_PRIMARY_CONTAINER:-dnsguard-prod-bind-primary-$RUN_ID}"
BIND_SECONDARY_1_CONTAINER="${BIND_SECONDARY_1_CONTAINER:-dnsguard-prod-bind-secondary-1-$RUN_ID}"
BIND_SECONDARY_2_CONTAINER="${BIND_SECONDARY_2_CONTAINER:-dnsguard-prod-bind-secondary-2-$RUN_ID}"
BIND_PRIMARY_HOST_PORT="${BIND_PRIMARY_HOST_PORT:-17353}"
BIND_SECONDARY_1_HOST_PORT="${BIND_SECONDARY_1_HOST_PORT:-17354}"
BIND_SECONDARY_2_HOST_PORT="${BIND_SECONDARY_2_HOST_PORT:-17355}"
export BIND_NETWORK_NAME DNSGUARD_INTERNAL_NETWORK_NAME DNSGUARD_INTERNAL_SUBNET BIND_PRIMARY_CONTAINER BIND_SECONDARY_1_CONTAINER BIND_SECONDARY_2_CONTAINER
export BIND_PRIMARY_HOST_PORT BIND_SECONDARY_1_HOST_PORT BIND_SECONDARY_2_HOST_PORT
PROJECT="dnsguard-production-acceptance"
RUNTIME="$ROOT_DIR/tests/docker-production-runtime"
DATA_DIR="$RUNTIME/data"
SECRET_DIR="$RUNTIME/secrets"
TLS_DIR="$RUNTIME/tls"
BIND_LOG_DIR="$RUNTIME/bind-logs"
ENV_FILE="$RUNTIME/dnsguard.env"
KEY_FILE="$SECRET_DIR/rpz-manager.key"
COOKIE_JAR="$RUNTIME/cookies.txt"
REPORT="$RUNTIME/acceptance-report.md"
WEB_HOST_PORT="${DNSGUARD_WEB_PORT:-19443}"
BASE_URL="https://127.0.0.1:$WEB_HOST_PORT"
COMPOSE=(docker compose -p "$PROJECT" -f "$ROOT_DIR/compose.yaml" -f "$ROOT_DIR/tests/docker-production-bind-net.yaml")
declare -a BIND_COMPOSE=(docker compose -p "$BIND_PROJECT" -f "$BIND_DIR/compose.yaml")

declare -a CASE_NAMES=()
declare -a CASE_STATUS=()
declare -a CASE_EVIDENCE=()

log() { printf '[docker-production] %s\n' "$*"; }

record_case() {
  local name="$1" status="$2" evidence="$3"
  CASE_NAMES+=("$name")
  CASE_STATUS+=("$status")
  CASE_EVIDENCE+=("$evidence")
  printf '%-42s %s\n' "$status" "$name"
}

run_case() {
  local name="$1" fn="$2" evidence result
  evidence="$RUNTIME/evidence/${#CASE_NAMES[@]}-${name// /_}.log"
  mkdir -p "$RUNTIME/evidence"
  set +e
  (set -e; "$fn") >"$evidence" 2>&1
  result=$?
  set -e
  if ((result == 0)); then
    record_case "$name" PASS "$evidence"
  else
    record_case "$name" FAIL "$evidence"
  fi
}

require_tools() {
  local missing=() tool
  for tool in docker curl openssl python3 go npm; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  python3 -c 'import bcrypt' >/dev/null 2>&1 || missing+=("python3-bcrypt")
  if ((${#missing[@]})); then
    log "NOT RUN: missing ${missing[*]}"
    exit 2
  fi
  docker info >/dev/null 2>&1 || { log 'NOT RUN: Docker daemon unavailable'; exit 2; }
}

compose() { "${COMPOSE[@]}" "$@"; }
bind_compose() { "${BIND_COMPOSE[@]}" "$@"; }

json_field() {
  local field="$1"
  python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$field"
}

decode_captcha() {
  local svg="$1"
  python3 - "$ROOT_DIR/server/captcha.go" "$svg" <<'PY'
import re, sys
from pathlib import Path
source = Path(sys.argv[1]).read_text()
svg = sys.argv[2]
glyphs = {}
for char, body in re.findall(r"'([^'])': \{([^}]*)\}", source):
    rows = re.findall(r'"([01]{5})"', body)
    if len(rows) == 7:
        glyphs[char] = rows
rects = {(int(x), int(y)) for x, y in re.findall(r'<rect x="(\d+)" y="(\d+)" width="3" height="3"', svg)}
answer = []
for index in range(4):
    observed = {(row, column) for row in range(7) for column in range(5)
                if (39 + index * 18 + column * 3, 8 + row * 4) in rects}
    matches = []
    for char, rows in glyphs.items():
        expected = {(row, column) for row, pattern in enumerate(rows)
                    for column, bit in enumerate(pattern) if bit == '1'}
        if expected == observed:
            matches.append(char)
    if len(matches) != 1:
        raise SystemExit(f'captcha glyph {index} ambiguous: {matches!r}')
    answer.append(matches[0])
print(''.join(answer))
PY
}

prepare_runtime() {
  compose down --remove-orphans >/dev/null 2>&1 || true
  bind_compose down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$BIND_RUNTIME"
  mkdir -p "$BIND_RUNTIME/keys" "$BIND_RUNTIME/primary-data" "$BIND_RUNTIME/primary-logs" \
    "$BIND_RUNTIME/secondary-1-data" "$BIND_RUNTIME/secondary-1-logs" \
    "$BIND_RUNTIME/secondary-2-data" "$BIND_RUNTIME/secondary-2-logs"
  local bind_secret
  bind_secret="$(openssl rand -base64 32 | tr -d '\n')"
  printf 'key "rpz-manager" {\n    algorithm hmac-sha256;\n    secret "%s";\n};\n' "$bind_secret" >"$BIND_RUNTIME/keys/rpz-manager.key"
  chmod 0640 "$BIND_RUNTIME/keys/rpz-manager.key"
  chown 53:53 "$BIND_RUNTIME/keys/rpz-manager.key"
  cat >"$BIND_RUNTIME/primary-data/rpz.local.zone" <<'EOF'
$TTL 60
$ORIGIN rpz.local.
@ IN SOA localhost. hostmaster.localhost. (1 1h 15m 30d 60)
  IN NS localhost.
EOF
  cp "$BIND_RUNTIME/primary-data/rpz.local.zone" "$BIND_RUNTIME/secondary-1-data/rpz.local.zone"
  cp "$BIND_RUNTIME/primary-data/rpz.local.zone" "$BIND_RUNTIME/secondary-2-data/rpz.local.zone"
  cat >"$BIND_RUNTIME/secondary-2-data/app.test.zone" <<'EOF'
$TTL 1
$ORIGIN app.test.
@ IN SOA ns.app.test. hostmaster.app.test. (1 1h 15m 30d 60)
  IN NS ns.app.test.
ns IN A 192.0.2.1
passthru IN A 192.0.2.10
redirect IN A 192.0.2.20
wild IN A 192.0.2.30
EOF
  cp "$BIND_RUNTIME/secondary-2-data/app.test.zone" "$BIND_RUNTIME/primary-data/app.test.zone"
  cp "$BIND_RUNTIME/secondary-2-data/app.test.zone" "$BIND_RUNTIME/secondary-1-data/app.test.zone"
  chmod -R 0775 "$BIND_RUNTIME"/*-data "$BIND_RUNTIME"/*-logs
  chown -R 53:53 "$BIND_RUNTIME"/*-data "$BIND_RUNTIME"/*-logs
  bind_compose up -d >/dev/null
  for _ in $(seq 1 60); do
    if docker exec "$BIND_PRIMARY_CONTAINER" dig +tcp +time=1 +tries=1 @127.0.0.1 rpz.local SOA +short 2>/dev/null | grep -q '[0-9]'; then
      break
    fi
    sleep 0.5
  done
  docker exec "$BIND_PRIMARY_CONTAINER" dig +tcp +time=2 +tries=1 @127.0.0.1 rpz.local SOA +short
  for container in "$BIND_SECONDARY_1_CONTAINER" "$BIND_SECONDARY_2_CONTAINER"; do
    docker exec "$container" rndc retransfer rpz.local >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
      if docker exec "$container" dig +tcp +time=1 +tries=1 @127.0.0.1 rpz.local SOA +short 2>/dev/null | grep -q '[0-9]'; then
        break
      fi
      sleep 0.5
    done
    docker exec "$container" dig +tcp +time=2 +tries=1 @127.0.0.1 rpz.local SOA +short
  done
  rm -rf "$RUNTIME"
  mkdir -p "$DATA_DIR/rpz" "$SECRET_DIR" "$TLS_DIR" "$BIND_LOG_DIR"
  cp "$BIND_RUNTIME/keys/rpz-manager.key" "$KEY_FILE"
  chmod 0640 "$KEY_FILE"
  chown 10001:10001 "$KEY_FILE"
  cat >"$DATA_DIR/initialization.json" <<'EOF'
{
  "status": "completed",
  "version": 1,
  "completedAt": "2026-01-01T00:00:00Z",
  "username": "admin",
  "zone": "rpz.local",
  "primary": "bind-primary",
  "secondaryCount": 2
}
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$TLS_DIR/privkey.pem" -out "$TLS_DIR/fullchain.pem" \
    -subj '/CN=localhost' >/dev/null 2>&1
  chmod 0644 "$TLS_DIR/fullchain.pem"
  chown 101:101 "$TLS_DIR/privkey.pem"
  chmod 0640 "$TLS_DIR/privkey.pem"

  python3 - "$DATA_DIR" <<'PY'
import json, os, pathlib, sys
from bcrypt import hashpw, gensalt
root = pathlib.Path(sys.argv[1])
auth = {
    'username': 'admin',
    'passwordHash': hashpw(b'test-password', gensalt()).decode(),
    'mustChangePassword': False,
}
nodes = [
    {'id':'primary-1','name':'bind-primary','role':'primary','address':'172.32.0.10:53'},
    {'id':'secondary-1','name':'bind-secondary-1','role':'secondary','address':'172.32.0.11:53'},
    {'id':'secondary-2','name':'bind-secondary-2','role':'secondary','address':'172.32.0.12:53'},
]
state = {'nodes':nodes, 'rules':[], 'published':[], 'versions':[], 'rulesRevision':0}
files = {
    'auth.json': auth,
    'dns-nodes.json': nodes,
    'dns-state.json': state,
    'publish-jobs.json': [],
    'audit.json': [],
    'telegram.json': {},
}
for name, value in files.items():
    path = root / name
    path.write_text(json.dumps(value, indent=2) + '\n')
    os.chmod(path, 0o600 if name == 'auth.json' else 0o640)
PY
  chown -R 10001:10001 "$DATA_DIR"
  chmod 0750 "$DATA_DIR" "$DATA_DIR/rpz"
  AUTH_SECRET="$(openssl rand -hex 32)"
  MONITORING_TOKEN="$(openssl rand -hex 32)"
  cat >"$ENV_FILE" <<EOF
APP_ENV=production
AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_SECRET=$AUTH_SECRET
MONITORING_TOKEN=$MONITORING_TOKEN
AUTH_FILE=/var/lib/dnsguard/auth.json
DNS_NODE_CONFIG_FILE=/var/lib/dnsguard/dns-nodes.json
INITIALIZATION_FILE=/var/lib/dnsguard/initialization.json
DNS_NODE_ALLOWED_CIDRS=172.32.0.0/24
DNS_NODE_ADDRESSES=primary-1=172.32.0.10:53,secondary-1=172.32.0.11:53,secondary-2=172.32.0.12:53
RPZ_ZONE=rpz.local
RPZ_PUBLISH_MODE=nsupdate
RPZ_PRIMARY=172.32.0.10
RPZ_PRIMARY_PORT=53
RPZ_KEY_FILE=/run/dnsguard-secrets/rpz-manager.key
RPZ_ARTIFACT_FILE=/var/lib/dnsguard/rpz/rpz.local.db
RPZ_PUBLISH_JOBS_FILE=/var/lib/dnsguard/publish-jobs.json
RPZ_PUBLISH_TIMEOUT_SECONDS=15
RPZ_PUBLISH_RETRIES=2
RPZ_PUBLISH_RETRY_BACKOFF_SECONDS=1
DNS_STATE_FILE=/var/lib/dnsguard/dns-state.json
AUDIT_FILE=/var/lib/dnsguard/audit.json
AUDIT_MAX_ENTRIES=2000
AUDIT_ROTATE_BYTES=5242880
AUDIT_ROTATE_BACKUPS=3
TELEGRAM_CONFIG_FILE=/var/lib/dnsguard/telegram.json
DNS_HEALTH_CACHE_SECONDS=1
DNS_HEALTH_INTERVAL_SECONDS=2
TRUST_PROXY_TLS=true
TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=172.28.0.0/24
LISTEN_ADDR=0.0.0.0:8080
EOF
  chmod 0640 "$ENV_FILE"
}

start_stack() {
  export DNSGUARD_ENV_FILE="$ENV_FILE"
  export DNSGUARD_DATA_DIR="$DATA_DIR"
  export DNSGUARD_SECRET_DIR="$SECRET_DIR"
  export DNSGUARD_TLS_DIR="$TLS_DIR"
  export DNSGUARD_BIND_LOG_DIR="$BIND_LOG_DIR"
  export DNSGUARD_WEB_PORT="$WEB_HOST_PORT"
  export DNSGUARD_WEB_BIND_IP=127.0.0.1
  export DNSGUARD_API_IMAGE=dnsguard-api:1.0.0
  export DNSGUARD_WEB_IMAGE=dnsguard-web:1.0.0
  if [[ "${SKIP_BUILD:-false}" != true ]]; then
    compose build
  fi
  compose up -d
  for _ in $(seq 1 60); do
    if curl -kfsS "$BASE_URL/api/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  compose ps
  compose logs --no-color
  return 1
}

login() {
  local captcha_json captcha_id captcha_svg captcha_code csrf
  rm -f "$COOKIE_JAR"
  captcha_json="$(curl -kfsS "$BASE_URL/api/auth/captcha")"
  captcha_id="$(printf '%s' "$captcha_json" | json_field id)"
  captcha_svg="$(printf '%s' "$captcha_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["svg"])')"
  captcha_code="$(decode_captcha "$captcha_svg")"
  curl -kfsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    --data "{\"username\":\"admin\",\"password\":\"test-password\",\"captchaId\":\"$captcha_id\",\"captcha\":\"$captcha_code\"}" \
    "$BASE_URL/api/auth/login" >/dev/null
  csrf="$(awk '$6 == "dnsguard_csrf" {print $7}' "$COOKIE_JAR")"
  [[ -n "$csrf" ]]
  printf '%s' "$csrf"
}

case_image_security() {
  docker run --rm --entrypoint sh dnsguard-api:1.0.0 -c '! command -v go && ! command -v node && ! command -v npm'
  [[ "$(docker image inspect dnsguard-api:1.0.0 --format '{{.Config.User}}')" == '10001:10001' ]]
  [[ "$(docker image inspect dnsguard-web:1.0.0 --format '{{.Config.User}}')" != '0' ]]
}

case_runtime_security() {
  [[ "$(compose exec -T dnsguard-api id -u)" == '10001' ]]
  compose exec -T dnsguard-api test -r /run/dnsguard-secrets/rpz-manager.key
  local published_ports
  published_ports="$(docker inspect "${PROJECT}-dnsguard-api-1" --format '{{json .NetworkSettings.Ports}}')"
  python3 - "$published_ports" <<'PY'
import json, sys
ports = json.loads(sys.argv[1]) or {}
assert all(value is None for value in ports.values()), ports
PY
  [[ "$(stat -c '%a' "$KEY_FILE")" == '640' ]]
}

case_auth_and_https() {
  [[ "$(curl -ksS -o /dev/null -w '%{http_code}' "$BASE_URL/api/dns/rpz")" == '401' ]]
  curl -kfsS "$BASE_URL/" | grep -q 'DNSGuard\|域盾'
  csrf="$(login)"
  curl -kfsS -b "$COOKIE_JAR" "$BASE_URL/api/auth/me" | grep -q '"authenticated":true'
  [[ -n "$csrf" ]]
}

wait_bind_answer() {
  local container="$1" name="$2" expected="$3" answer=''
  for _ in $(seq 1 240); do
    answer="$(docker exec "$container" dig +short +recurse @127.0.0.1 "$name" A 2>/dev/null || true)"
    if [[ "$answer" == "$expected" ]]; then return 0; fi
    sleep 0.25
  done
  echo "container=$container name=$name answer=$answer expected=$expected"
  return 1
}

case_real_publish_and_transfer() {
  local csrf rule job_id status primary_serial secondary_one secondary_two
  csrf="$(login)"
  rule="$(curl -kfsS -b "$COOKIE_JAR" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    --data '{"domain":"redirect.app.test","type":"A","value":"192.0.2.55","reason":"compose RPZ redirect"}' \
    "$BASE_URL/api/dns/rpz")"
  printf '%s' "$rule" | grep -q 'redirect.app.test'
  curl -kfsS -b "$COOKIE_JAR" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    --data '{"domain":"wild.app.test","type":"A","value":"192.0.2.66","reason":"compose wildcard redirect"}' \
    "$BASE_URL/api/dns/rpz" >/dev/null
  curl -kfsS -b "$COOKIE_JAR" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    --data '{"domain":"passthru.app.test","type":"CNAME","value":"","reason":"compose passthru"}' \
    "$BASE_URL/api/dns/rpz" >/dev/null
  job_id="$(curl -kfsS -b "$COOKIE_JAR" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    --data '{}' "$BASE_URL/api/dns/rpz/publish" | json_field id)"
  [[ -n "$job_id" ]]
  status=''
  for _ in $(seq 1 30); do
    status="$(curl -kfsS -b "$COOKIE_JAR" "$BASE_URL/api/dns/rpz/jobs/$job_id" | json_field status)"
    [[ "$status" == succeeded || "$status" == published ]] && break
    [[ "$status" == failed || "$status" == sync_exception || "$status" == reconcile_required ]] && return 1
    sleep 1
  done
  [[ "$status" == succeeded || "$status" == published ]]
  primary_serial="$(docker exec "$BIND_PRIMARY_CONTAINER" dig +short @127.0.0.1 rpz.local SOA | awk '{print $3}')"
  secondary_one="$(docker exec "$BIND_SECONDARY_1_CONTAINER" dig +short @127.0.0.1 rpz.local SOA | awk '{print $3}')"
  secondary_two="$(docker exec "$BIND_SECONDARY_2_CONTAINER" dig +short @127.0.0.1 rpz.local SOA | awk '{print $3}')"
  echo "job_status=$status primary_serial=$primary_serial secondary_1_serial=$secondary_one secondary_2_serial=$secondary_two"
  [[ -n "$primary_serial" && "$primary_serial" == "$secondary_one" && "$primary_serial" == "$secondary_two" ]]
  echo 'nsupdate accepted by Primary and all three nodes reported the same SOA Serial'
}

case_actual_rpz_policy_effects() {
  local answer_one answer_two
  answer_one="$(docker exec "$BIND_SECONDARY_1_CONTAINER" dig +short +recurse @127.0.0.1 redirect.app.test A)"
  answer_two="$(docker exec "$BIND_SECONDARY_2_CONTAINER" dig +short +recurse @127.0.0.1 redirect.app.test A)"
  echo "legacy_authoritative_answer_secondary_1=$answer_one secondary_2=$answer_two"
  [[ "$answer_one" == '192.0.2.20' && "$answer_two" == '192.0.2.20' ]]
  wait_bind_answer "$BIND_PRIMARY_CONTAINER" redirect.app.test 192.0.2.55
  wait_bind_answer "$BIND_SECONDARY_1_CONTAINER" redirect.app.test 192.0.2.55
  wait_bind_answer "$BIND_SECONDARY_2_CONTAINER" redirect.app.test 192.0.2.55
  wait_bind_answer "$BIND_PRIMARY_CONTAINER" foo.wild.app.test 192.0.2.66
  wait_bind_answer "$BIND_SECONDARY_1_CONTAINER" foo.wild.app.test 192.0.2.66
  wait_bind_answer "$BIND_SECONDARY_2_CONTAINER" foo.wild.app.test 192.0.2.66
  wait_bind_answer "$BIND_PRIMARY_CONTAINER" passthru.app.test 192.0.2.10
  echo 'exact A redirect, wildcard A redirect, and CNAME passthru verified after RPZ reload'
}

case_persistence_after_recreate() {
  local csrf
  grep -q 'redirect.app.test' "$DATA_DIR/dns-state.json"
  compose down
  compose up -d
  for _ in $(seq 1 45); do
    curl -kfsS "$BASE_URL/api/health" >/dev/null 2>&1 && break
    sleep 1
  done
  csrf="$(login)"
  curl -kfsS -b "$COOKIE_JAR" "$BASE_URL/api/dns/rpz" | grep -q 'redirect.app.test'
  [[ -n "$csrf" ]]
}

case_security_failure_without_auth() {
  local bad_env="$RUNTIME/bad.env" bad_project="${PROJECT}-bad"
  cp "$ENV_FILE" "$bad_env"
  sed -i 's/^AUTH_ENABLED=true$/AUTH_ENABLED=false/' "$bad_env"
  DNSGUARD_ENV_FILE="$bad_env" DNSGUARD_DATA_DIR="$RUNTIME/bad-data" \
    DNSGUARD_SECRET_DIR="$SECRET_DIR" DNSGUARD_TLS_DIR="$TLS_DIR" \
    DNSGUARD_BIND_LOG_DIR="$BIND_LOG_DIR" DNSGUARD_WEB_PORT="$((WEB_HOST_PORT + 1))" \
    docker compose -p "$bad_project" -f "$ROOT_DIR/compose.yaml" \
    --env-file "$bad_env" up -d >/dev/null 2>&1 || true
  sleep 3
  local state
  state="$(docker inspect "${bad_project}-dnsguard-api-1" --format '{{.State.Status}}' 2>/dev/null || true)"
  docker compose -p "$bad_project" -f "$ROOT_DIR/compose.yaml" --env-file "$bad_env" down --remove-orphans >/dev/null 2>&1 || true
  [[ "$state" == exited || "$state" == restarting || "$state" == created || -z "$state" ]]
}

case_api_port_isolated() {
  local published_ports
  published_ports="$(docker inspect "${PROJECT}-dnsguard-api-1" --format '{{json .NetworkSettings.Ports}}')"
  python3 - "$published_ports" <<'PY'
import json, sys
ports = json.loads(sys.argv[1]) or {}
assert all(value is None for value in ports.values()), ports
PY
}

write_report() {
  mkdir -p "$RUNTIME"
  {
    echo '# DNSGuard V1.0 Docker Compose 生产部署验收报告'
    echo
    echo "- 执行时间（UTC）：$RUN_ID"
    echo '- 隔离 BIND：tests/docker-production-bind，172.32.0.0/24'
    echo '- 生产连接：无；生产 BIND、生产 TSIG 未访问'
    echo
    echo '| 用例 | 结果 | 证据 |'
    echo '|---|---|---|'
    for i in "${!CASE_NAMES[@]}"; do
      echo "| ${CASE_NAMES[$i]} | ${CASE_STATUS[$i]} | \`${CASE_EVIDENCE[$i]}\` |"
    done
    echo
    echo 'PASS 仅表示本次在本地 Docker 隔离环境中真实执行并满足断言；未执行项目不得标记为 PASS。'
  } >"$REPORT"
}

cleanup() {
  local code=$?
  compose logs --no-color >"$RUNTIME/compose.log" 2>&1 || true
  compose down --remove-orphans >/dev/null 2>&1 || true
  bind_compose logs --no-color >"$RUNTIME/bind-compose.log" 2>&1 || true
  bind_compose down --remove-orphans >/dev/null 2>&1 || true
  write_report || true
  return "$code"
}

main() {
  require_tools
  trap cleanup EXIT
  prepare_runtime
  start_stack
  run_case 'multi-stage-images-and-non-root-runtime' case_image_security
  run_case 'api-secret-permissions-and-no-published-api-port' case_runtime_security
  run_case 'https-authentication-and-csrf-path' case_auth_and_https
  run_case 'real-nsupdate-tsig-and-secondary-transfer' case_real_publish_and_transfer
  run_case 'actual-rpz-recursive-policy-effects' case_actual_rpz_policy_effects
  run_case 'recreate-preserves-json-state-and-audit' case_persistence_after_recreate
  run_case 'unsafe-auth-configuration-fails-closed' case_security_failure_without_auth
  run_case 'api-port-remains-internal-only' case_api_port_isolated
  write_report
  if printf '%s\n' "${CASE_STATUS[@]}" | grep -q '^FAIL$'; then return 1; fi
}

main "$@"
