#!/usr/bin/env bash
set -Eeuo pipefail

# One-command, isolated real API/Web + BIND E2E. This script only owns resources
# bearing its unique RUN_ID; it never runs a global Docker cleanup operation.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_ID="${E2E_RUN_ID:-$(date -u +%Y%m%dt%H%M%S)-$$}"
PROJECT="dnsguard-e2e-${RUN_ID}"
BIND_NETWORK="dnsguard-e2e-bind-${RUN_ID}"
INTERNAL_NETWORK="dnsguard-e2e-internal-${RUN_ID}"
SUBNET="${E2E_BIND_SUBNET:-172.34.0.0/24}"
INTERNAL_SUBNET="${E2E_INTERNAL_SUBNET:-172.35.0.0/24}"
PRIMARY_IP="172.34.0.10"
SECONDARY_IP="172.34.0.11"
UPSTREAM_IP="172.34.0.12"
API_IP=""
BIND_PRIMARY="${PROJECT}-bind-primary"
BIND_SECONDARY="${PROJECT}-bind-secondary"
BIND_UPSTREAM="${PROJECT}-bind-upstream"
BIND_DIR="$ROOT_DIR/tests/e2e/runtime/$RUN_ID/bind"
RUNTIME="$ROOT_DIR/tests/e2e/runtime/$RUN_ID"
DATA_DIR="$RUNTIME/data"
SECRET_DIR="$RUNTIME/secrets"
TLS_DIR="$RUNTIME/tls"
BIND_LOG_DIR="$RUNTIME/bind-logs"
ENV_FILE="$RUNTIME/dnsguard.env"
BUILD_OVERRIDE="$RUNTIME/compose.e2e-build.yaml"
REPORT="$RUNTIME/acceptance-report.md"
COOKIE_JAR="$RUNTIME/cookies.txt"
STORAGE_STATE="$ROOT_DIR/tests/e2e/playwright-storage.json"
WEB_PORT="${E2E_WEB_PORT:-}"
WEB_URL="https://127.0.0.1:${WEB_PORT}"
KEY_FILE="$SECRET_DIR/rpz-manager.key"
KEEP="${E2E_KEEP:-false}"
DNSSEC_OBSERVE="${E2E_DNSSEC_OBSERVE:-false}"
DNSSEC_OBSERVATION_STATUS="NOT RUN"
DNSSEC_OBSERVATION_DETAIL=""
RPZ_PACKAGE_ROOT=""
COMPOSE=(docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$ROOT_DIR/compose.yaml" -f "$ROOT_DIR/compose.bind-network.yaml" -f "$BUILD_OVERRIDE")
BIND_COMPOSE=(docker compose -p "$PROJECT-bind" -f "$BIND_DIR/compose.yaml")
declare -a CASE_NAMES=() CASE_STATUS=() CASE_EVIDENCE=()

log() { printf '[e2e] %s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
chown_web_tls() {
  if chown 101:101 "$@" 2>/dev/null; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n chown 101:101 "$@" 2>/dev/null; then
    return 0
  fi
  printf '无法将隔离 Web TLS 路径设置为 UID/GID 101；请提供本地测试目录的 chown 权限\n' >&2
  return 1
}
record() { CASE_NAMES+=("$1"); CASE_STATUS+=("$2"); CASE_EVIDENCE+=("$3"); printf '%-56s %s\n' "$2" "$1"; }
case_run() {
  local name="$1" fn="$2" evidence safe_name code
  mkdir -p "$RUNTIME/evidence"
  safe_name="${name//[^a-zA-Z0-9_-]/_}"
  evidence="$RUNTIME/evidence/${#CASE_NAMES[@]}-${safe_name}.log"
  set +e; (set -e; "$fn") >"$evidence" 2>&1; code=$?; set -e
  if ((code == 0)); then
    record "$name" PASS "$evidence"
  elif ((code == 2)); then
    record "$name" 'NOT RUN' "$evidence"
  else
    record "$name" FAIL "$evidence"
  fi
}
require_case() {
  local name="$1" fn="$2" evidence
  case_run "$name" "$fn"
  evidence="${CASE_EVIDENCE[$((${#CASE_EVIDENCE[@]} - 1))]}"
  if [[ "${CASE_STATUS[$((${#CASE_STATUS[@]} - 1))]}" != PASS ]]; then
    printf '验收证据（不含密钥）：%s\n' "$evidence" >&2
    sed -n '1,240p' "$evidence" >&2 || true
    die "验收项失败：$name；详见报告"
  fi
}
need() { command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"; }
require_tools() {
  local tool
  for tool in docker curl openssl dig python3 npm npx; do need "$tool"; done
  docker info >/dev/null 2>&1 || die 'Docker Engine 不可用或当前用户无 Docker Socket 权限'
  docker compose version >/dev/null 2>&1 || die 'Docker Compose Plugin 不可用'
  if [[ -z "${E2E_WEB_PORT:-}" ]]; then
    WEB_PORT="$(python3 - <<'PY'
import socket
for port in range(28443, 28550):
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        sock.close()
        continue
    sock.close()
    print(port)
    break
else:
    raise SystemExit("没有找到可用的本地 Web 端口")
PY
    )"
  else
    python3 - "$WEB_PORT" <<'PY'
import socket,sys
sock=socket.socket()
try: sock.bind(("127.0.0.1",int(sys.argv[1])))
except OSError: raise SystemExit("指定的 E2E_WEB_PORT 已被占用")
finally: sock.close()
PY
  fi
  WEB_URL="https://127.0.0.1:${WEB_PORT}"
  if [[ -z "${E2E_BIND_SUBNET:-}" && -z "${E2E_INTERNAL_SUBNET:-}" ]]; then
    read -r SUBNET INTERNAL_SUBNET < <(python3 - <<'PY'
import ipaddress
import json
import subprocess

raw = subprocess.check_output(["docker", "network", "inspect", *subprocess.check_output(
    ["docker", "network", "ls", "-q"], text=True).split()], text=True)
used = []
def add_network(value):
    if value and value != "default":
        try:
            used.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass

for item in json.loads(raw):
    for config in item.get("IPAM", {}).get("Config") or []:
        add_network(config.get("Subnet"))

# Docker bridge selection must also avoid the host's routed and assigned
# networks.  A Docker subnet overlapping an interface (for example the
# machine's VPN or cloud NIC) can make a loopback-published test Web port
# hang or reset even though the container itself is healthy.
if subprocess.call(["sh", "-c", "command -v ip >/dev/null 2>&1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
    for command in (("ip", "-4", "-j", "route", "show"), ("ip", "-4", "-j", "addr", "show")):
        try:
            host_data = json.loads(subprocess.check_output(command, text=True))
        except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
            continue
        if command[3] == "route":
            for route in host_data:
                add_network(route.get("dst"))
        else:
            for interface in host_data:
                for address in interface.get("addr_info", []):
                    if address.get("family") == "inet":
                        local = address.get("local")
                        prefix = address.get("prefixlen")
                        if local is not None and prefix is not None:
                            add_network(f"{local}/{prefix}")

for third in range(30, 250, 2):
    candidate = [ipaddress.ip_network(f"172.{third}.0.0/24"), ipaddress.ip_network(f"172.{third + 1}.0.0/24")]
    if all(not any(net.overlaps(existing) for existing in used) for net in candidate):
        print(*candidate)
        break
else:
    raise SystemExit("没有找到不与既有 Docker 网络冲突的隔离网段")
PY
    )
    [[ -n "$SUBNET" && -n "$INTERNAL_SUBNET" ]] || die '无法选择隔离 Docker 网段'
  fi
  PRIMARY_IP="$(python3 -c 'import ipaddress,sys; print(str(list(ipaddress.ip_network(sys.argv[1]).hosts())[9]))' "$SUBNET")"
  SECONDARY_IP="$(python3 -c 'import ipaddress,sys; print(str(list(ipaddress.ip_network(sys.argv[1]).hosts())[10]))' "$SUBNET")"
  UPSTREAM_IP="$(python3 -c 'import ipaddress,sys; print(str(list(ipaddress.ip_network(sys.argv[1]).hosts())[11]))' "$SUBNET")"
  [[ ! -e "$BIND_NETWORK" ]] || die '内部脚本错误：网络变量不是路径'
  if docker network inspect "$BIND_NETWORK" >/dev/null 2>&1 || docker network inspect "$INTERNAL_NETWORK" >/dev/null 2>&1; then
    die '测试资源名冲突；不会删除或接管既有 Docker 网络'
  fi
  if docker ps -a --format '{{.Names}}' | grep -Fxq "$BIND_PRIMARY" || docker ps -a --format '{{.Names}}' | grep -Fxq "$BIND_SECONDARY"; then
    die '测试容器名冲突；不会删除或接管既有容器'
  fi
}
cleanup() {
  local code=$?
  write_report || true
  if [[ "$KEEP" != true ]]; then
    "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
    "${BIND_COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
    docker network rm "$BIND_NETWORK" >/dev/null 2>&1 || true
  fi
  rm -f -- "$STORAGE_STATE"
  if [[ -f "$REPORT" ]]; then log "报告：$REPORT"; fi
  return "$code"
}
trap cleanup EXIT

write_zone_files() {
  mkdir -p "$BIND_DIR"/primary/{etc-bind,lib-bind,cache-bind,log-bind} "$BIND_DIR"/secondary/{etc-bind,lib-bind,cache-bind,log-bind} "$BIND_DIR"/upstream/{etc-bind,lib-bind,cache-bind,log-bind} "$BIND_DIR"/primary/etc-bind/keys "$BIND_DIR"/secondary/etc-bind/keys
  cat >"$BIND_DIR/primary/lib-bind/rpz.local.zone" <<'EOF'
$TTL 60
$ORIGIN rpz.local.
@ IN SOA ns.rpz.local. hostmaster.rpz.local. (1 1h 15m 30d 60)
  IN NS ns.rpz.local.
ns IN A 172.34.0.10
EOF
  cat >"$BIND_DIR/primary/lib-bind/global-deny.rpz.local.zone" <<'EOF'
$TTL 60
$ORIGIN global-deny.rpz.local.
@ IN SOA ns.global-deny.rpz.local. hostmaster.rpz.local. (1 1h 15m 30d 60)
  IN NS ns.global-deny.rpz.local.
ns IN A 172.34.0.10
* IN CNAME .
EOF
  cat >"$BIND_DIR/upstream/lib-bind/app.test.zone" <<EOF
\$TTL 60
\$ORIGIN app.test.
@ IN SOA ns.app.test. hostmaster.app.test. (1 1h 15m 30d 60)
  IN NS ns.app.test.
ns IN A $UPSTREAM_IP
baseline IN A 192.0.2.42
allowed IN A 192.0.2.43
deep.allowed IN A 192.0.2.44
redirect IN A 192.0.2.50
EOF
  cp "$BIND_DIR/primary/lib-bind/"rpz.local.zone "$BIND_DIR/primary/lib-bind/"global-deny.rpz.local.zone "$BIND_DIR/secondary/lib-bind/"
  cp "$KEY_FILE" "$BIND_DIR/primary/etc-bind/keys/rpz-manager.key"
  cp "$KEY_FILE" "$BIND_DIR/secondary/etc-bind/keys/rpz-manager.key"
  chmod 0640 "$KEY_FILE" "$BIND_DIR"/*/etc-bind/keys/rpz-manager.key
  # GitHub-hosted runners execute this script as an unprivileged user.  Prefer
  # the direct ownership change, then use the runner's non-interactive sudo;
  # never prompt or weaken host permissions.  The final chmod fallback keeps
  # the test-only tree readable/writable by the container when neither is
  # available, without touching any host or production path.
  if ! chown -R 53:53 "$BIND_DIR"/*/etc-bind/keys "$BIND_DIR"/*/lib-bind "$BIND_DIR"/*/cache-bind "$BIND_DIR"/*/log-bind 2>/dev/null; then
    if command -v sudo >/dev/null 2>&1 && sudo -n chown -R 53:53 "$BIND_DIR"/*/etc-bind/keys "$BIND_DIR"/*/lib-bind "$BIND_DIR"/*/cache-bind "$BIND_DIR"/*/log-bind 2>/dev/null; then
      :
    else
      chmod -R u+rwX,go+rwX "$BIND_DIR"/*/etc-bind/keys "$BIND_DIR"/*/lib-bind "$BIND_DIR"/*/cache-bind "$BIND_DIR"/*/log-bind
      chmod 0644 "$BIND_DIR"/*/etc-bind/keys/rpz-manager.key
      printf '%s\n' '[e2e] no ownership change available; using isolated test-tree permissions' >&2
    fi
  fi
}
write_named_conf() {
  local upstream_logging=''
  if [[ "$DNSSEC_OBSERVE" == true ]]; then
    upstream_logging='logging { channel dnssec_query_log { file "/var/log/bind/query.log" versions 2 size 1m; severity info; print-time yes; }; category queries { dnssec_query_log; }; };'
  fi
  cat >"$BIND_DIR/primary/etc-bind/named.conf" <<EOF
options { directory "/var/cache/bind"; listen-on port 53 { any; }; listen-on-v6 { none; }; recursion no; allow-query { 127.0.0.1; $API_IP; $SECONDARY_IP; }; allow-recursion { none; }; dnssec-validation no; };
EOF
  cat >"$BIND_DIR/secondary/etc-bind/named.conf" <<EOF
options { directory "/var/cache/bind"; listen-on port 53 { any; }; listen-on-v6 { none; }; recursion yes; forward only; forwarders { $UPSTREAM_IP; }; allow-query { 127.0.0.1; $API_IP; }; allow-recursion { 127.0.0.1; $API_IP; }; allow-query-cache { 127.0.0.1; $API_IP; }; dnssec-validation no; };
EOF
  mkdir -p "$BIND_DIR/upstream/etc-bind/keys"
  cat >"$BIND_DIR/upstream/etc-bind/named.conf" <<EOF
$upstream_logging
options { directory "/var/cache/bind"; listen-on port 53 { any; }; listen-on-v6 { none; }; recursion no; allow-query { $SECONDARY_IP; 127.0.0.1; }; dnssec-validation no; };
zone "app.test" { type primary; file "/var/lib/bind/app.test.zone"; };
EOF
}
write_bind_compose() {
  cat >"$BIND_DIR/compose.yaml" <<EOF
services:
  primary:
    image: internetsystemsconsortium/bind9:9.20
    container_name: $BIND_PRIMARY
    command: ["-f", "-g", "-c", "/etc/bind/named.conf"]
    networks: { bind: { ipv4_address: $PRIMARY_IP } }
    volumes:
      - ./primary/etc-bind:/etc/bind
      - ./primary/lib-bind:/var/lib/bind
      - ./primary/cache-bind:/var/cache/bind
      - ./primary/log-bind:/var/log/bind
  secondary:
    image: internetsystemsconsortium/bind9:9.20
    container_name: $BIND_SECONDARY
    command: ["-f", "-g", "-c", "/etc/bind/named.conf"]
    networks: { bind: { ipv4_address: $SECONDARY_IP } }
    volumes:
      - ./secondary/etc-bind:/etc/bind
      - ./secondary/lib-bind:/var/lib/bind
      - ./secondary/cache-bind:/var/cache/bind
      - ./secondary/log-bind:/var/log/bind
  upstream:
    image: internetsystemsconsortium/bind9:9.20
    container_name: ${PROJECT}-bind-upstream
    command: ["-f", "-g", "-c", "/etc/bind/named.conf"]
    networks: { bind: { ipv4_address: $UPSTREAM_IP } }
    volumes:
      - ./upstream/etc-bind:/etc/bind
      - ./upstream/lib-bind:/var/lib/bind
      - ./upstream/cache-bind:/var/cache/bind
      - ./upstream/log-bind:/var/log/bind
networks:
  bind:
    name: $BIND_NETWORK
    external: true
EOF
}
write_env() {
  mkdir -p "$DATA_DIR/bootstrap" "$DATA_DIR/rpz" "$SECRET_DIR" "$TLS_DIR" "$BIND_LOG_DIR"
  printf '%s\n' "e2e-bootstrap-${RUN_ID}-token-0123456789" >"$SECRET_DIR/bootstrap.token"
  chmod 0600 "$SECRET_DIR/bootstrap.token"
  printf 'key "rpz-manager" { algorithm hmac-sha256; secret "%s"; };\n' "$(openssl rand -base64 32 | tr -d '\n')" >"$KEY_FILE"
  chmod 0640 "$KEY_FILE"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$TLS_DIR/privkey.pem" -out "$TLS_DIR/fullchain.pem" -subj '/CN=localhost' >/dev/null 2>&1
  chmod 0750 "$TLS_DIR"
  chmod 0640 "$TLS_DIR/privkey.pem"; chmod 0644 "$TLS_DIR/fullchain.pem"
  chown_web_tls "$TLS_DIR" "$TLS_DIR/privkey.pem"
  cat >"$DATA_DIR/bootstrap/whitelist-seed.json" <<'EOF'
{"version":1,"source":"rpz-connect","mode":"global","generatedAt":"2026-01-01T00:00:00Z","zone":"rpz.local.","rules":[{"domain":"allowed.app.test","type":"CNAME","action":"passthru","value":"rpz-passthru.","reason":"isolated e2e allowlist"}]}
EOF
  chmod 0640 "$DATA_DIR/bootstrap/whitelist-seed.json"
  cat >"$ENV_FILE" <<EOF
DNSGUARD_PLATFORM_ONLY=true
RPZ_DEFAULT_DENY_MODE=global
RPZ_GLOBAL_DENY_SETUP_DEFERRED=true
DNSGUARD_INTERNAL_NETWORK_NAME=$INTERNAL_NETWORK
DNSGUARD_INTERNAL_SUBNET=$INTERNAL_SUBNET
DNSGUARD_BIND_NETWORK=$BIND_NETWORK
DNSGUARD_DATA_DIR=$DATA_DIR
DNSGUARD_SECRET_DIR=$SECRET_DIR
DNSGUARD_TLS_DIR=$TLS_DIR
DNSGUARD_BIND_LOG_DIR=$BIND_LOG_DIR
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
DNS_NODE_ALLOWED_CIDRS=$SUBNET
RPZ_ZONE=rpz.local
RPZ_PRIMARY=$PRIMARY_IP
RPZ_PRIMARY_PORT=53
RPZ_KEY_FILE=/run/dnsguard-secrets/rpz-manager.key
RPZ_PUBLISH_MODE=nsupdate
RPZ_ARTIFACT_FILE=/var/lib/dnsguard/rpz/rpz.local.db
RPZ_PUBLISH_JOBS_FILE=/var/lib/dnsguard/publish-jobs.json
DNS_STATE_FILE=/var/lib/dnsguard/dns-state.json
AUDIT_FILE=/var/lib/dnsguard/audit.json
TLD_STATE_FILE=/var/lib/dnsguard/tld-state.json
TLD_DENY_ARTIFACT_FILE=/var/lib/dnsguard/rpz/tld-deny.rpz.local.db
RPZ_GLOBAL_DENY_ZONE=global-deny.rpz.local
RPZ_GLOBAL_DENY_RECURSOR=$SECONDARY_IP:53
RPZ_GLOBAL_DENY_CHECK_NAME=baseline.app.test
RPZ_GLOBAL_DENY_BASELINE_FILE=/var/lib/dnsguard/global-deny-baseline.json
RPZ_WHITELIST_SEED_FILE=/var/lib/dnsguard/bootstrap/whitelist-seed.json
LISTEN_ADDR=0.0.0.0:8080
TRUST_PROXY_TLS=true
TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=$INTERNAL_SUBNET
DNSGUARD_WEB_BIND_IP=127.0.0.1
DNSGUARD_WEB_PORT=$WEB_PORT
DNSGUARD_ENV_FILE=$ENV_FILE
E2E_API_UID_GID=$(id -u):$(id -g)
EOF
  # The production Compose file deliberately uses network: host while
  # downloading build dependencies. GitHub-hosted BuildKit runners may require
  # an explicit network.host entitlement for that setting. The isolated E2E
  # build does not need host networking, so override only the build-time
  # network without changing the production Compose architecture or runtime
  # networks.
  cat >"$BUILD_OVERRIDE" <<'EOF'
services:
  dnsguard-api:
    # The isolated finalizer reads the same temporary bind-mounted JSON state
    # from the host. Match the test-only container UID to the invoking user;
    # production Compose still runs the API as 10001:10001.
    user: "${E2E_API_UID_GID}"
    build:
      network: default
  dnsguard-web:
    build:
      network: default
EOF
  chmod 0640 "$ENV_FILE"
  chmod 0750 "$DATA_DIR" "$SECRET_DIR" "$DATA_DIR/bootstrap" "$DATA_DIR/rpz"
}
start_api_web() {
  export DNSGUARD_ENV_FILE="$ENV_FILE" DNSGUARD_DATA_DIR="$DATA_DIR" DNSGUARD_SECRET_DIR="$SECRET_DIR" DNSGUARD_TLS_DIR="$TLS_DIR" DNSGUARD_BIND_LOG_DIR="$BIND_LOG_DIR" DNSGUARD_BIND_NETWORK="$BIND_NETWORK" DNSGUARD_INTERNAL_NETWORK_NAME="$INTERNAL_NETWORK" DNSGUARD_WEB_PORT="$WEB_PORT" DNSGUARD_WEB_BIND_IP=127.0.0.1
  docker network create --driver bridge --subnet "$SUBNET" "$BIND_NETWORK" >/dev/null
  "${COMPOSE[@]}" build >/dev/null
  "${COMPOSE[@]}" up -d >/dev/null
  for _ in $(seq 1 90); do curl -kfsS "$WEB_URL/api/health" >/dev/null 2>&1 && return 0; sleep 1; done
  "${COMPOSE[@]}" ps; "${COMPOSE[@]}" logs --no-color; return 1
}
start_bind() {
  local api_id
  api_id="$("${COMPOSE[@]}" ps -q dnsguard-api)"
  API_IP="$(docker inspect "$api_id" | python3 -c '
import json
import sys

network = sys.argv[1]
data = json.load(sys.stdin)[0]
print(data["NetworkSettings"]["Networks"][network]["IPAddress"])
' "$BIND_NETWORK")"
  [[ "$API_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die '无法确定隔离 API 在 BIND 网络中的地址'
  write_zone_files; write_named_conf; write_bind_compose
  docker run --rm --entrypoint named-checkconf \
    -v "$BIND_DIR/primary/etc-bind:/etc/bind:ro" -v "$BIND_DIR/primary/lib-bind:/var/lib/bind:ro" -v "$BIND_DIR/primary/cache-bind:/var/cache/bind:ro" \
    internetsystemsconsortium/bind9:9.20 -z /etc/bind/named.conf >/dev/null
  docker run --rm --entrypoint named-checkzone \
    -v "$BIND_DIR/primary/lib-bind:/var/lib/bind:ro" internetsystemsconsortium/bind9:9.20 \
    rpz.local /var/lib/bind/rpz.local.zone >/dev/null
  docker run --rm --entrypoint named-checkconf \
    -v "$BIND_DIR/secondary/etc-bind:/etc/bind:ro" -v "$BIND_DIR/secondary/lib-bind:/var/lib/bind:ro" -v "$BIND_DIR/secondary/cache-bind:/var/cache/bind:ro" \
    internetsystemsconsortium/bind9:9.20 -z /etc/bind/named.conf >/dev/null
  docker run --rm --entrypoint named-checkconf \
    -v "$BIND_DIR/upstream/etc-bind:/etc/bind:ro" -v "$BIND_DIR/upstream/lib-bind:/var/lib/bind:ro" -v "$BIND_DIR/upstream/cache-bind:/var/cache/bind:ro" \
    internetsystemsconsortium/bind9:9.20 -z /etc/bind/named.conf >/dev/null
  docker run --rm --entrypoint named-checkzone \
    -v "$BIND_DIR/upstream/lib-bind:/var/lib/bind:ro" internetsystemsconsortium/bind9:9.20 \
    app.test /var/lib/bind/app.test.zone >/dev/null
  "${BIND_COMPOSE[@]}" up -d >/dev/null
  for _ in $(seq 1 90); do
    docker exec "$BIND_PRIMARY" dig +tcp +time=1 +tries=1 @127.0.0.1 version.bind CH TXT +noall +comments >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec "$BIND_PRIMARY" dig +tcp +time=2 +tries=1 @127.0.0.1 version.bind CH TXT +noall +comments >/dev/null
  for _ in $(seq 1 90); do
    docker exec "$BIND_SECONDARY" dig +tcp +time=1 +tries=1 @127.0.0.1 version.bind CH TXT +noall +comments >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
browser_package() {
  local bootstrap_token
  bootstrap_token="$(cat "$SECRET_DIR/bootstrap.token")"
  export E2E_REAL_BASE_URL="$WEB_URL" E2E_BOOTSTRAP_TOKEN="$bootstrap_token" E2E_TSIG_PATH=/run/dnsguard-secrets/rpz-manager.key E2E_PRIMARY="$PRIMARY_IP:53" E2E_SECONDARY="$SECONDARY_IP:53" E2E_REAL_PHASE=package E2E_PACKAGE_PATH="$RUNTIME/dnsguard-rpz-package.zip" E2E_PLATFORM_STORAGE_STATE="$RUNTIME/package-storage.json"
  (cd "$ROOT_DIR" && npx playwright test tests/ui/real-deployment.spec.ts --project=desktop)
}
browser_bind() {
  local bootstrap_token
  bootstrap_token="$(cat "$SECRET_DIR/bootstrap.token")"
  # Platform bootstrap creates the administrator but does not create a
  # browser login session. Authenticate through the same captcha/login API
  # used by the real UI before opening the second browser phase.
  create_storage_state
  export E2E_REAL_BASE_URL="$WEB_URL" E2E_STORAGE_STATE="$STORAGE_STATE" E2E_BOOTSTRAP_TOKEN="$bootstrap_token" E2E_TSIG_PATH=/run/dnsguard-secrets/rpz-manager.key E2E_PRIMARY="$PRIMARY_IP:53" E2E_SECONDARY="$SECONDARY_IP:53" E2E_REAL_PHASE=bind
  (cd "$ROOT_DIR" && npx playwright test tests/ui/real-deployment.spec.ts --project=desktop)
}
api_gate_before_bind() {
  local code
  code="$(curl -ksS -o "$RUNTIME/pre-bind-publish.json" -w '%{http_code}' -X POST "$WEB_URL/api/dns/rpz/publish" -H 'Content-Type: application/json' -d '{}')"
  [[ "$code" == 428 ]]
}
extract_package_safely() {
  local archive="$RUNTIME/dnsguard-rpz-package.zip" target="$RUNTIME/rpz-package" nested
  [[ -s "$archive" ]] || { printf 'FAIL: Web did not produce an RPZ package: %s\n' "$archive"; return 1; }
  mkdir -p "$target"
  python3 - "$archive" "$target" <<'PY'
import pathlib, stat, sys, zipfile
archive, target = sys.argv[1:]
root = pathlib.Path(target).resolve()
with zipfile.ZipFile(archive) as package:
    for member in package.infolist():
        name = member.filename
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts:
            raise SystemExit(f'unsafe archive path: {name}')
        mode = (member.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise SystemExit(f'symbolic links are not allowed: {name}')
        destination = (root / pathlib.Path(*path.parts)).resolve()
        if root != destination and root not in destination.parents:
            raise SystemExit(f'archive path escapes target: {name}')
        if member.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        with package.open(member) as source, destination.open('xb') as output:
            output.write(source.read())
        destination.chmod(0o750 if member.filename.endswith('.sh') else 0o640)
PY
  # The API ZIP intentionally contains a single top-level package directory.
  # Accept that layout as well as a flat archive, but never guess through more
  # than one directory: the safe extractor above already rejected traversal.
  nested=""
  if [[ -x "$target/apply-rpz-config.sh" && -x "$target/verify-rpz-config.sh" ]]; then
    nested="$target"
  elif [[ -x "$target/dnsguard-rpz-package/apply-rpz-config.sh" && -x "$target/dnsguard-rpz-package/verify-rpz-config.sh" ]]; then
    nested="$target/dnsguard-rpz-package"
  fi
  [[ -n "$nested" ]] || { printf 'FAIL: extracted RPZ package is incomplete\n'; return 1; }
  RPZ_PACKAGE_ROOT="$nested"
}
apply_downloaded_package() {
  local package_root host_etc host_lib bind_user bind_group
  extract_package_safely
  package_root="$RPZ_PACKAGE_ROOT"
  host_etc="$BIND_DIR/primary/etc-bind"
  host_lib="$BIND_DIR/primary/lib-bind"
  bind_user="$(id -un)"
  bind_group="$(id -gn)"
  # The package is generated for the container's canonical paths. For the
  # host-side apply script, translate only the isolated test tree paths, then
  # restore the canonical paths before named loads the mounted configuration.
  sed -i "s#/etc/bind#$host_etc#g; s#/var/lib/bind#$host_lib#g; s#/var/cache/bind#$BIND_DIR/secondary/lib-bind#g" "$package_root"/config/*.conf
  env BIND_CONFIG_ROOT="$host_etc" BIND_NAMED_CONF="$host_etc/named.conf" PRIMARY_DATA_DIR="$host_lib/dnsguard-rpz-primary" SECONDARY_DATA_DIR="$BIND_DIR/secondary/lib-bind/dnsguard-rpz-secondary" BIND_USER="$bind_user" BIND_GROUP="$bind_group" bash "$package_root/apply-rpz-config.sh" --check primary
  env BIND_CONFIG_ROOT="$host_etc" BIND_NAMED_CONF="$host_etc/named.conf" PRIMARY_DATA_DIR="$host_lib/dnsguard-rpz-primary" SECONDARY_DATA_DIR="$BIND_DIR/secondary/lib-bind/dnsguard-rpz-secondary" BIND_USER="$bind_user" BIND_GROUP="$bind_group" bash "$package_root/apply-rpz-config.sh" --apply primary
  host_etc="$BIND_DIR/secondary/etc-bind"
  host_lib="$BIND_DIR/secondary/lib-bind"
  sed -i "s#${BIND_DIR}/primary/etc-bind#$host_etc#g; s#${BIND_DIR}/primary/lib-bind#$host_lib#g" "$package_root"/config/*.conf
  env BIND_CONFIG_ROOT="$host_etc" BIND_NAMED_CONF="$host_etc/named.conf" PRIMARY_DATA_DIR="$BIND_DIR/primary/lib-bind/dnsguard-rpz-primary" SECONDARY_DATA_DIR="$host_lib/dnsguard-rpz-secondary" BIND_USER="$bind_user" BIND_GROUP="$bind_group" bash "$package_root/apply-rpz-config.sh" --check secondary
  env BIND_CONFIG_ROOT="$host_etc" BIND_NAMED_CONF="$host_etc/named.conf" PRIMARY_DATA_DIR="$BIND_DIR/primary/lib-bind/dnsguard-rpz-primary" SECONDARY_DATA_DIR="$host_lib/dnsguard-rpz-secondary" BIND_USER="$bind_user" BIND_GROUP="$bind_group" bash "$package_root/apply-rpz-config.sh" --apply secondary
  # Restore paths as seen inside the BIND containers after the host-side
  # preview/apply/verify completed. No production path is touched.
  sed -i "s#${BIND_DIR}/primary/etc-bind#/etc/bind#g; s#${BIND_DIR}/primary/lib-bind#/var/lib/bind#g; s#${BIND_DIR}/secondary/etc-bind#/etc/bind#g; s#${BIND_DIR}/secondary/lib-bind#/var/lib/bind#g" "$BIND_DIR/primary/etc-bind/named.conf" "$BIND_DIR/primary/etc-bind/dnsguard-rpz/config"/*.conf "$BIND_DIR/secondary/etc-bind/named.conf" "$BIND_DIR/secondary/etc-bind/dnsguard-rpz/config"/*.conf
  if ! chown -R 53:53 "$BIND_DIR/primary/etc-bind/dnsguard-rpz" "$BIND_DIR/primary/lib-bind/dnsguard-rpz-primary" "$BIND_DIR/secondary/etc-bind/dnsguard-rpz" "$BIND_DIR/secondary/lib-bind/dnsguard-rpz-secondary" 2>/dev/null; then
    if command -v sudo >/dev/null 2>&1 && sudo -n chown -R 53:53 "$BIND_DIR/primary/etc-bind/dnsguard-rpz" "$BIND_DIR/primary/lib-bind/dnsguard-rpz-primary" "$BIND_DIR/secondary/etc-bind/dnsguard-rpz" "$BIND_DIR/secondary/lib-bind/dnsguard-rpz-secondary" 2>/dev/null; then
      :
    else
      chmod -R u+rwX,go+rX "$BIND_DIR/primary/etc-bind/dnsguard-rpz" "$BIND_DIR/primary/lib-bind/dnsguard-rpz-primary" "$BIND_DIR/secondary/etc-bind/dnsguard-rpz" "$BIND_DIR/secondary/lib-bind/dnsguard-rpz-secondary"
    fi
  fi
  docker exec "$BIND_PRIMARY" named-checkconf -z /etc/bind/named.conf
  docker exec "$BIND_SECONDARY" named-checkconf -z /etc/bind/named.conf
  docker kill -s HUP "$BIND_PRIMARY" >/dev/null
  docker kill -s HUP "$BIND_SECONDARY" >/dev/null
  for _ in $(seq 1 90); do
    docker exec "$BIND_PRIMARY" dig +tcp +time=1 +tries=1 @127.0.0.1 rpz.local SOA +short 2>/dev/null | grep -q '[0-9]' && break
    sleep 1
  done
  docker exec "$BIND_PRIMARY" dig +tcp +time=2 +tries=1 @127.0.0.1 rpz.local SOA +short >/dev/null
  for _ in $(seq 1 90); do
    docker exec "$BIND_SECONDARY" dig +tcp +time=1 +tries=1 @127.0.0.1 rpz.local SOA +short 2>/dev/null | grep -q '[0-9]' && return 0
    sleep 1
  done
  return 1
}
enable_global_deny() {
  sed -i 's#// zone "global-deny.rpz.local";#zone "global-deny.rpz.local";#' "$BIND_DIR/primary/etc-bind/dnsguard-rpz/config/response-policy.conf" "$BIND_DIR/secondary/etc-bind/dnsguard-rpz/config/response-policy.conf"
  # Keep the isolated recursive fixture aligned with the documented
  # qname-wait-recurse=no profile. The option is part of the response-policy
  # statement and therefore belongs on its closing line.
  # This is test-only BIND configuration; the product never changes an
  # administrator's production recursion settings.
  sed -i 's/^};$/} qname-wait-recurse no;/' "$BIND_DIR/primary/etc-bind/dnsguard-rpz/config/response-policy.conf" "$BIND_DIR/secondary/etc-bind/dnsguard-rpz/config/response-policy.conf"
  docker exec "$BIND_PRIMARY" named-checkconf -z /etc/bind/named.conf >/dev/null
  docker exec "$BIND_SECONDARY" named-checkconf -z /etc/bind/named.conf >/dev/null
  docker exec "$BIND_PRIMARY" rndc reload >/dev/null 2>&1 || docker kill -s HUP "$BIND_PRIMARY" >/dev/null
  docker exec "$BIND_SECONDARY" rndc reload >/dev/null 2>&1 || docker kill -s HUP "$BIND_SECONDARY" >/dev/null
  for _ in $(seq 1 30); do
    if ! docker exec "$BIND_SECONDARY" dig +short +recurse @127.0.0.1 baseline.app.test A 2>/dev/null | grep -q '192.0.2.42'; then return 0; fi
    sleep 1
  done
  return 1
}
check_real_dns() {
  local p s r allow nested redirect
  p="$(docker exec "$BIND_PRIMARY" dig +short +norecurse @127.0.0.1 rpz.local SOA | awk 'NF>=3{print $3; exit}')"
  s="$(docker exec "$BIND_SECONDARY" dig +short +norecurse @127.0.0.1 rpz.local SOA | awk 'NF>=3{print $3; exit}')"
  r="$(docker exec "$BIND_SECONDARY" dig +short +recurse @127.0.0.1 baseline.app.test A || true)"
  for _ in $(seq 1 60); do
    allow="$(docker exec "$BIND_SECONDARY" dig +short +recurse @127.0.0.1 allowed.app.test A || true)"
    nested="$(docker exec "$BIND_SECONDARY" dig +short +recurse @127.0.0.1 deep.allowed.app.test A || true)"
    redirect="$(docker exec "$BIND_SECONDARY" dig +short +recurse @127.0.0.1 redirect.app.test A || true)"
    [[ "$allow" == '192.0.2.43' && "$nested" == '192.0.2.44' && "$redirect" == '192.0.2.99' ]] && break
    sleep 1
  done
  printf 'business_primary_serial=%s\nbusiness_secondary_serial=%s\nrecursive_baseline=%s\nwhitelist=%s\nnested_whitelist=%s\na_redirect=%s\n' "$p" "$s" "$r" "$allow" "$nested" "$redirect"
  [[ -n "$p" && "$p" == "$s" && "$r" == '192.0.2.42' && "$allow" == '192.0.2.43' && "$nested" == '192.0.2.44' && "$redirect" == '192.0.2.99' ]]
}
check_network_exposure() {
  local host_ip primary_rcode secondary_rcode transfer_rcode update_code response published
  if ! host_ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '$1 !~ /^127\./ && $1 !~ /:/ && NF {print; exit}')"; then
    printf 'NOT RUN: 无法确定隔离测试主机的非回环 IPv4 地址\n'
    return 2
  fi
  if curl -ksS --connect-timeout 2 --max-time 3 -o /dev/null "$WEB_URL"; then
    :
  else
    printf 'FAIL: 回环 Web 地址不可访问\n'
    return 1
  fi
  if curl -ksS --connect-timeout 2 --max-time 3 -o /dev/null "https://${host_ip}:${WEB_PORT}" 2>/dev/null; then
    printf 'FAIL: Web 从非回环地址可达：%s\n' "$host_ip"
    return 1
  fi
  if published="$("${COMPOSE[@]}" port dnsguard-api 8080 2>/dev/null)"; then
    while IFS= read -r published_line; do
      # Compose may report an unpublished port as :0, 0.0.0.0:0, or :::0
      # depending on the Docker/Compose version. Only a non-zero host port is
      # a publication; do not reject the intentionally unpublished :0 form.
      [[ -z "$published_line" || "$published_line" =~ :0$ ]] && continue
      printf 'FAIL: API 发布了宿主机端口：%s\n' "$published_line"
      return 1
    done <<< "$published"
  fi
  for bind_container in "$BIND_PRIMARY" "$BIND_SECONDARY" "$BIND_UPSTREAM"; do
    if published="$(docker port "$bind_container" 2>/dev/null)" && [[ -n "$published" ]]; then
      printf 'FAIL: BIND 测试容器发布了宿主机端口：%s (%s)\n' "$bind_container" "$published"
      return 1
    fi
  done
  primary_rcode=''; secondary_rcode=''; transfer_rcode=''
  for _ in {1..20}; do
    response="$(docker exec "$BIND_UPSTREAM" dig +tcp +time=1 +tries=1 +noall +comments @"$PRIMARY_IP" baseline.app.test A 2>/dev/null || true)"
    primary_rcode="$(printf '%s\n' "$response" | awk '/status:/{gsub(",", "", $6); print $6; exit}')"
    response="$(docker exec "$BIND_UPSTREAM" dig +tcp +time=1 +tries=1 +noall +comments @"$SECONDARY_IP" baseline.app.test A 2>/dev/null || true)"
    secondary_rcode="$(printf '%s\n' "$response" | awk '/status:/{gsub(",", "", $6); print $6; exit}')"
    response="$(docker exec "$BIND_UPSTREAM" dig +tcp +time=1 +tries=1 +noall +comments @"$PRIMARY_IP" rpz.local AXFR 2>/dev/null || true)"
    transfer_rcode="$(printf '%s\n' "$response" | awk '/status:/{gsub(",", "", $6); print $6; exit}')"
    [[ "$primary_rcode" == REFUSED && "$secondary_rcode" == REFUSED && "$transfer_rcode" == REFUSED ]] && break
    sleep 1
  done
  [[ "$primary_rcode" == REFUSED ]] || { printf 'FAIL: Primary 未授权递归查询 RCODE=%s\n' "${primary_rcode:-empty}"; return 1; }
  [[ "$secondary_rcode" == REFUSED ]] || { printf 'FAIL: Secondary 未授权递归查询 RCODE=%s\n' "${secondary_rcode:-empty}"; return 1; }
  if [[ "${E2E_EXPECT_RPZ_ACL:-false}" == true ]]; then
    [[ "$transfer_rcode" == REFUSED ]] || { printf 'FAIL: 已加载 RPZ 的未授权 AXFR RCODE=%s\n' "${transfer_rcode:-empty}"; return 1; }
  else
    [[ "$transfer_rcode" == REFUSED || "$transfer_rcode" == NOTAUTH ]] || { printf 'FAIL: 未配置 RPZ 时的未授权 AXFR RCODE=%s\n' "${transfer_rcode:-empty}"; return 1; }
  fi
  set +e
  printf 'server %s\nzone rpz.local\nupdate add unauthorized.rpz.local. 60 TXT denied\nsend\n' "$PRIMARY_IP" | docker exec -i "$BIND_UPSTREAM" nsupdate -v >/dev/null 2>&1
  update_code=$?
  set -e
  ((update_code != 0)) || { printf 'FAIL: 未授权动态更新未被拒绝\n'; return 1; }
  printf 'PASS: Web 仅回环可达；Primary/Secondary 未授权递归=%s/%s；未授权 AXFR=%s、UPDATE 均拒绝\n' "$primary_rcode" "$secondary_rcode" "$transfer_rcode"
}
check_global_dns() {
  local p s trigger r allow nested redirect unknown unknown_rcode
  p="$(docker exec "$BIND_PRIMARY" dig +short +norecurse @127.0.0.1 global-deny.rpz.local SOA | awk 'NF>=3{print $3; exit}')"
  s="$(docker exec "$BIND_SECONDARY" dig +short +norecurse @127.0.0.1 global-deny.rpz.local SOA | awk 'NF>=3{print $3; exit}')"
  trigger="$(docker exec "$BIND_SECONDARY" dig +short +norecurse @127.0.0.1 '*.global-deny.rpz.local.' CNAME || true)"
  r="$(docker exec "$BIND_SECONDARY" dig +short +recurse @127.0.0.1 baseline.app.test A || true)"
  allow="$(docker exec "$BIND_SECONDARY" dig +short +recurse @127.0.0.1 allowed.app.test A || true)"
  nested="$(docker exec "$BIND_SECONDARY" dig +short +recurse @127.0.0.1 deep.allowed.app.test A || true)"
  redirect="$(docker exec "$BIND_SECONDARY" dig +short +recurse @127.0.0.1 redirect.app.test A || true)"
  unknown="blocked.${RUN_ID}.outside.test"
  unknown_rcode="$(docker exec "$BIND_SECONDARY" dig +recurse +noall +comments @127.0.0.1 "$unknown" A | awk '/status:/{gsub(",", "", $6); print $6; exit}')"
  printf 'global_primary_serial=%s\nglobal_secondary_serial=%s\ntrigger=%s\nrecursive_after_deny=%s\nwhitelist_after_deny=%s\nnested_whitelist_after_deny=%s\na_redirect_after_deny=%s\nunknown_qname=%s\nunknown_rcode=%s\n' "$p" "$s" "$trigger" "$r" "$allow" "$nested" "$redirect" "$unknown" "$unknown_rcode"
  [[ -n "$p" && "$p" == "$s" && "$trigger" == '.' && -z "$r" && "$allow" == '192.0.2.43' && "$nested" == '192.0.2.44' && "$redirect" == '192.0.2.99' && "$unknown_rcode" == 'NXDOMAIN' ]]
}
check_dnssec_upstream_observation() {
  local qname_do0 qname_do1 rcode_do0 rcode_do1 log_file label_base observed_do0 observed_do1
  if [[ "$DNSSEC_OBSERVE" != true ]]; then
    printf 'NOT RUN: set E2E_DNSSEC_OBSERVE=true to enable isolated upstream query logging\n'
    DNSSEC_OBSERVATION_STATUS='NOT RUN'
    DNSSEC_OBSERVATION_DETAIL='opt-in only; no external DNSLog or production resolver was used'
    return 2
  fi
  log_file="$BIND_DIR/upstream/log-bind/query.log"
  label_base="dnssec-${RUN_ID//[^[:alnum:]]/}"
  qname_do0="${label_base}-do0.app.test."
  qname_do1="${label_base}-do1.app.test."
  for _ in $(seq 1 20); do
    [[ -f "$log_file" ]] && break
    sleep 1
  done
  [[ -f "$log_file" ]] || {
    printf 'FAIL: controlled upstream query log was not created: %s\n' "$log_file"
    DNSSEC_OBSERVATION_STATUS='FAIL'
    DNSSEC_OBSERVATION_DETAIL='upstream logging was requested but no log file was available'
    return 1
  }
  rcode_do0="$(docker exec "$BIND_SECONDARY" dig +nodnssec +recurse +time=2 +tries=1 +noall +comments @127.0.0.1 "$qname_do0" A 2>/dev/null | awk '/status:/{gsub(",", "", $6); print $6; exit}' || true)"
  rcode_do1="$(docker exec "$BIND_SECONDARY" dig +dnssec +recurse +time=2 +tries=1 +noall +comments @127.0.0.1 "$qname_do1" A 2>/dev/null | awk '/status:/{gsub(",", "", $6); print $6; exit}' || true)"
  sleep 2
  observed_do0=false
  observed_do1=false
  if grep -Fq -- "${qname_do0%.}" "$log_file"; then
    observed_do0=true
  fi
  if grep -Fq -- "${qname_do1%.}" "$log_file"; then
    observed_do1=true
  fi
  printf 'do0_qname=%s\ndo0_rcode=%s\ndo0_upstream_observed=%s\ndo1_qname=%s\ndo1_rcode=%s\ndo1_upstream_observed=%s\n' "$qname_do0" "$rcode_do0" "$observed_do0" "$qname_do1" "$rcode_do1" "$observed_do1"
  if [[ "$rcode_do0" != NXDOMAIN || "$rcode_do1" != NXDOMAIN ]]; then
    DNSSEC_OBSERVATION_STATUS='FAIL'
    DNSSEC_OBSERVATION_DETAIL="client RCODEs were not both NXDOMAIN (DO=0: ${rcode_do0:-empty}, DO=1: ${rcode_do1:-empty})"
    return 1
  fi
  if [[ "$observed_do0" == true || "$observed_do1" == true ]]; then
    DNSSEC_OBSERVATION_STATUS='FAIL'
    DNSSEC_OBSERVATION_DETAIL='the complete randomized QNAME appeared in the isolated authoritative upstream query log; NXDOMAIN is not treated as containment'
    return 1
  fi
  DNSSEC_OBSERVATION_STATUS='PASS'
  DNSSEC_OBSERVATION_DETAIL='both queries returned NXDOMAIN and the complete randomized QNAME was not observed in the isolated upstream log'
}
create_storage_state() {
  local captcha_json captcha_id captcha_svg captcha_code
  captcha_json="$(curl -kfsS "$WEB_URL/api/auth/captcha")"
  captcha_id="$(printf '%s' "$captcha_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
  captcha_svg="$(printf '%s' "$captcha_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["svg"])')"
  captcha_code="$(python3 - "$ROOT_DIR/server/captcha.go" "$captcha_svg" <<'PY'
import re,sys
from pathlib import Path
src=Path(sys.argv[1]).read_text(); svg=sys.argv[2]; glyphs={}
for char,body in re.findall(r"'([^'])': \{([^}]*)\}",src):
 rows=re.findall(r'"([01]{5})"',body)
 if len(rows)==7:glyphs[char]=rows
rects={(int(x),int(y)) for x,y in re.findall(r'<rect x="(\d+)" y="(\d+)" width="3" height="3"',svg)}; out=[]
for i in range(4):
 obs={(r,c) for r in range(7) for c in range(5) if (39+i*18+c*3,8+r*4) in rects}; m=[]
 for ch,rows in glyphs.items():
  exp={(r,c) for r,p in enumerate(rows) for c,b in enumerate(p) if b=='1'}
  if exp==obs:m.append(ch)
 if len(m)!=1: raise SystemExit('captcha decode failed')
 out.append(m[0])
print(''.join(out))
PY
  )"
  curl -kfsS -D "$RUNTIME/login-headers.txt" -c "$COOKIE_JAR" -b "$COOKIE_JAR" -H 'Content-Type: application/json' --data "{\"username\":\"admin\",\"password\":\"e2e-admin-password-123\",\"captchaId\":\"$captcha_id\",\"captcha\":\"$captcha_code\"}" "$WEB_URL/api/auth/login" >"$RUNTIME/login-response.json"
  grep -q '"authenticated":true' "$RUNTIME/login-response.json" || die '隔离 API 登录未返回 authenticated=true'
  python3 - "$COOKIE_JAR" "$STORAGE_STATE" <<'PY'
import json,sys
from http.cookies import SimpleCookie
cookies=[]
headers=sys.argv[1].replace('cookies.txt','login-headers.txt')
for line in open(headers, encoding='utf-8'):
 if line.lower().startswith('set-cookie:'):
  jar=SimpleCookie(); jar.load(line.split(':',1)[1].strip())
  for name,morsel in jar.items():
   cookies.append({'name':name,'value':morsel.value,'domain':'127.0.0.1','path':morsel['path'] or '/', 'secure':True, 'httpOnly':name=='dnsguard_session','sameSite':'Lax'})
if not any(item['name']=='dnsguard_session' for item in cookies):
 raise SystemExit('login response did not set dnsguard_session')
json.dump({'cookies':cookies,'origins':[]},open(sys.argv[2],'w'))
PY
}
final_browser() {
  log 'final browser verification: API is rebuilt with deferred=false'
  create_storage_state
  export E2E_REAL_BASE_URL="$WEB_URL" E2E_STORAGE_STATE="$STORAGE_STATE" E2E_REAL_PHASE=final E2E_PRIMARY="$PRIMARY_IP:53" E2E_SECONDARY="$SECONDARY_IP:53"
  (cd "$ROOT_DIR" && npx playwright test tests/ui/real-deployment.spec.ts --project=desktop)
}
write_report() {
  mkdir -p "$RUNTIME"
  { echo '# DNSGuard isolated real E2E'; echo; echo "- run: $RUN_ID"; echo "- BIND image: internetsystemsconsortium/bind9:9.20"; echo "- resources: $PROJECT / $BIND_NETWORK / $INTERNAL_NETWORK"; echo '- topology: one Primary, one Secondary, and one isolated authoritative upstream fixture'; echo "- recursive profile: qname-wait-recurse no; DNSSEC DO=1/upstream observation: $DNSSEC_OBSERVATION_STATUS"; echo "- DNSSEC observation detail: $DNSSEC_OBSERVATION_DETAIL"; echo '- public DNSLog observation: NOT RUN; no public resolver or external DNSLog was used'; echo '- production resources and real secrets: not accessed'; echo; echo '| test | status | evidence |'; echo '|---|---|---|'; for i in "${!CASE_NAMES[@]}"; do printf "| %s | %s | \`%s\` |\\n" "${CASE_NAMES[$i]}" "${CASE_STATUS[$i]}" "${CASE_EVIDENCE[$i]}"; done; } >"$REPORT"
}
main() {
  require_tools; mkdir -p "$RUNTIME"; write_env; start_api_web
  case_run 'platform-first API/Web starts before BIND' true
  case_run 'publish gate rejects writes before BIND' api_gate_before_bind
  start_bind
  require_case 'network exposure and BIND ACL gate' check_network_exposure
  require_case 'real browser platform/package download flow' browser_package
  require_case 'real RPZ package preview/apply/verify and BIND reload' apply_downloaded_package
  E2E_EXPECT_RPZ_ACL=true require_case 'loaded BIND ACL gate' check_network_exposure
  require_case 'real browser BIND completion/package/whitelist flow' browser_bind
  require_case 'real BIND config and two RPZ zones loaded' check_real_dns
  enable_global_deny
  require_case 'Global Deny follows whitelist and baseline gate' check_global_dns
  case_run 'controlled DNSSEC DO=1 upstream observation' check_dnssec_upstream_observation
  DNSSEC_OBSERVATION_STATUS="${CASE_STATUS[$((${#CASE_STATUS[@]} - 1))]}"
  DNSSEC_OBSERVATION_DETAIL="see ${CASE_EVIDENCE[$((${#CASE_EVIDENCE[@]} - 1))]} for the separate DO=0 and DO=1 QNAME observations"
  export COMPOSE_PROJECT_NAME="$PROJECT" DNSGUARD_ENV_FILE="$ENV_FILE" DNSGUARD_BIND_NETWORK="$BIND_NETWORK" DNSGUARD_INTERNAL_NETWORK_NAME="$INTERNAL_NETWORK" DNSGUARD_DATA_DIR="$DATA_DIR" DNSGUARD_SECRET_DIR="$SECRET_DIR" DNSGUARD_TLS_DIR="$TLS_DIR" DNSGUARD_BIND_LOG_DIR="$BIND_LOG_DIR"
  export DNSGUARD_COMPOSE_OVERRIDE="$BUILD_OVERRIDE"
  if ! bash "$ROOT_DIR/scripts/finalize-global-deny.sh"; then
    die 'finalize-global-deny.sh 返回失败；保留隔离资源和报告供定位'
  fi
  log 'finalize-global-deny.sh completed; starting final browser verification'
  require_case 'real browser final verification and guide disappears' final_browser
  write_report
  if printf '%s\n' "${CASE_STATUS[@]}" | grep -q '^FAIL$'; then return 1; fi
}
main "$@"
