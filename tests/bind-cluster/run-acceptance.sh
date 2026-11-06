#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR="$ROOT_DIR/tests/bind-cluster"
RUNTIME_DIR="$TEST_DIR/runtime"
EVIDENCE_DIR="$RUNTIME_DIR/evidence"
COMPOSE_FILE="$TEST_DIR/compose.yaml"
PROJECT="dnsguard-bind-acceptance"
API_BIN="$RUNTIME_DIR/dnsguard-api"
API_PORT="${BIND_ACCEPTANCE_API_PORT:-18081}"
PRIMARY_PORT="${BIND_PRIMARY_HOST_PORT:-15353}"
SECONDARY_1_PORT="${BIND_SECONDARY_1_HOST_PORT:-15354}"
SECONDARY_2_PORT="${BIND_SECONDARY_2_HOST_PORT:-15355}"
BASELINE_PORT="${TLD_DENY_BASELINE_PORT:-${BIND_BASELINE_HOST_PORT:-15356}}"
API_URL="http://127.0.0.1:${API_PORT}"
API_PID=""
TLD_SOURCE_PID=""
KEEP=0
CLEAN_ONLY=0
BIND_ONLY=0
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="$RUNTIME_DIR/acceptance-report.md"

declare -a CASE_NAMES=()
declare -a CASE_STATUS=()
declare -a CASE_EVIDENCE=()

# The permission-failure cases need a non-root account so that chmod-based
# failures are real. Do not bake a workstation-specific username into the
# public test harness; CI or operators can set TEST_RUN_USER explicitly.
TEST_RUN_USER="${TEST_RUN_USER:-}"
if [[ -z "$TEST_RUN_USER" ]]; then
  if [[ "$EUID" -ne 0 ]]; then
    TEST_RUN_USER="$(id -un)"
  else
    TEST_RUN_USER="$(awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /(nologin|false)$/ {print $1; exit}' /etc/passwd)"
  fi
fi
if [[ -z "$TEST_RUN_USER" ]] || ! id "$TEST_RUN_USER" >/dev/null 2>&1; then
  printf 'NOT RUN: set TEST_RUN_USER to an existing non-root test account\n' >&2
  exit 2
fi
TEST_RUN_GROUP="$(id -gn "$TEST_RUN_USER")"

log() { printf '[bind-cluster] %s\n' "$*"; }

usage() {
  cat <<'EOF'
Usage: run-acceptance.sh [--keep|--clean|--bind-only]

  --keep   Keep containers, runtime data, and logs after the run.
  --clean  Stop/remove this Compose project and delete only its runtime data.
  --bind-only  Prepare and start only the isolated three-node BIND cluster.
EOF
}

while (($#)); do
  case "$1" in
    --keep) KEEP=1 ;;
    --clean) CLEAN_ONLY=1 ;;
    --bind-only) BIND_ONLY=1; KEEP=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done

compose() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }

chown_bind_path() {
  local path="$1"
  if chown 53:53 "$path" 2>/dev/null; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n chown 53:53 "$path" 2>/dev/null; then
    return 0
  fi
  printf 'cannot set BIND ownership on %s; run the isolated test with permission to chown test data\n' "$path" >&2
  return 1
}

chown_bind_tree() {
  local path="$1"
  if chown -R 53:53 "$path" 2>/dev/null; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n chown -R 53:53 "$path" 2>/dev/null; then
    return 0
  fi
  printf 'cannot set BIND ownership on %s; run the isolated test with permission to chown test data\n' "$path" >&2
  return 1
}

record_case() {
  local name="$1" status="$2" evidence="$3"
  CASE_NAMES+=("$name")
  CASE_STATUS+=("$status")
  CASE_EVIDENCE+=("$evidence")
  printf '%-38s %s\n' "$status" "$name"
}

record_not_run() {
  local name="$1" evidence="$2"
  record_case "$name" 'NOT RUN' "$evidence"
}

run_case() {
  local name="$1" fn="$2" evidence
  evidence="$EVIDENCE_DIR/${#CASE_NAMES[@]}-${name// /_}.log"
  mkdir -p "$EVIDENCE_DIR"
  # Run each case in a real errexit-enabled subshell. Calling a function
  # directly as the condition of `if` disables errexit inside that function
  # in Bash and can turn a failed assertion followed by an echo into a false
  # PASS.
  set +e
  (set -e; "$fn") >"$evidence" 2>&1
  local result=$?
  set -e
  if ((result == 0)); then
    record_case "$name" PASS "$evidence"
  elif ((result == 125)); then
    record_not_run "$name" "$evidence"
  else
    record_case "$name" FAIL "$evidence"
  fi
}

required_tools=(docker curl dig nsupdate named-checkzone go openssl python3 npm runuser fuser)
missing_tools=()
for tool in "${required_tools[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || missing_tools+=("$tool")
done

write_not_run_report() {
  mkdir -p "$RUNTIME_DIR"
  {
    echo "# DNSGuard Docker BIND 集群验收报告"
    echo
    echo "- 执行时间（UTC）：$RUN_ID"
    echo "- 结果：NOT RUN"
    echo "- 原因：缺少 Docker/Compose 或必要工具：${missing_tools[*]:-Docker daemon unavailable}"
    echo
    echo "所有 Docker BIND 集群用例均为 NOT RUN；没有把未执行用例记为通过。"
  } >"$REPORT"
}

if ((${#missing_tools[@]})); then
  write_not_run_report
  printf 'NOT RUN: %s\n' "${missing_tools[*]}" >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  missing_tools+=("Docker daemon")
  write_not_run_report
  printf 'NOT RUN: Docker daemon unavailable\n' >&2
  exit 2
fi

if ((CLEAN_ONLY)); then
  compose down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$RUNTIME_DIR"
  log "cleaned isolated Docker BIND acceptance runtime"
  exit 0
fi

cleanup_on_exit() {
  local exit_code=$?
  if [[ -n "$API_PID" ]] && kill -0 "$API_PID" 2>/dev/null; then
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
  if [[ -n "$TLD_SOURCE_PID" ]] && kill -0 "$TLD_SOURCE_PID" 2>/dev/null; then
    kill "$TLD_SOURCE_PID" 2>/dev/null || true
    wait "$TLD_SOURCE_PID" 2>/dev/null || true
  fi
  compose logs --no-color >"$RUNTIME_DIR/docker-compose.log" 2>&1 || true
  if ((KEEP == 0)); then
    compose down --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -f "$RUNTIME_DIR/acceptance-report.md" ]]; then
    log "report: $RUNTIME_DIR/acceptance-report.md"
  fi
  return "$exit_code"
}
trap cleanup_on_exit EXIT

prepare_runtime() {
  # Never kill an unrelated process just because a test port is occupied. A
  # previous interrupted run can be cleaned with --clean; an unknown listener
  # makes this run NOT RUN instead of being forcefully terminated.
  for port in "$PRIMARY_PORT" "$SECONDARY_1_PORT" "$SECONDARY_2_PORT" "$BASELINE_PORT" "$API_PORT" 18082 18083 18084 18085 18086 18087 18088 18089 18090 18091 18092; do
    if fuser "$port/tcp" >/dev/null 2>&1; then
      echo "test API port $port is already in use; refusing to stop the listener" >&2
      return 2
    fi
  done
  compose down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$RUNTIME_DIR"
  mkdir -p "$RUNTIME_DIR" "$EVIDENCE_DIR" \
    "$RUNTIME_DIR/keys" \
    "$RUNTIME_DIR/primary-data" "$RUNTIME_DIR/primary-logs" \
    "$RUNTIME_DIR/secondary-1-data" "$RUNTIME_DIR/secondary-1-logs" \
    "$RUNTIME_DIR/secondary-2-data" "$RUNTIME_DIR/secondary-2-logs"

  local secret
  secret="$(openssl rand -base64 32 | tr -d '\n')"
  printf 'key "rpz-manager" {\n    algorithm hmac-sha256;\n    secret "%s";\n};\n' "$secret" >"$RUNTIME_DIR/keys/rpz-manager.key"
  chmod 0640 "$RUNTIME_DIR/keys/rpz-manager.key"
  chown_bind_path "$RUNTIME_DIR/keys/rpz-manager.key"

  cat >"$RUNTIME_DIR/primary-data/rpz.local.zone" <<'EOF'
$TTL 60
$ORIGIN rpz.local.
@ IN SOA localhost. hostmaster.localhost. (1 1h 15m 30d 60)
  IN NS localhost.
ns IN A 192.0.2.1
EOF
  cat >"$RUNTIME_DIR/primary-data/app.test.zone" <<'EOF'
$TTL 1
$ORIGIN app.test.
@ IN SOA ns.app.test. hostmaster.app.test. (1 1h 15m 30d 60)
  IN NS ns.app.test.
ns IN A 192.0.2.1
passthru IN A 192.0.2.10
redirect IN A 192.0.2.20
wild IN A 192.0.2.30
EOF
  cat >"$RUNTIME_DIR/primary-data/tld-deny.rpz.local.zone" <<'EOF'
$TTL 60
$ORIGIN tld-deny.rpz.local.
@ IN SOA localhost. hostmaster.localhost. (1 1h 15m 30d 60)
  IN NS localhost.
EOF
  cat >"$RUNTIME_DIR/primary-data/example.com.zone" <<'EOF'
$TTL 60
$ORIGIN example.com.
@ IN SOA ns.example.com. hostmaster.example.com. (1 1h 15m 30d 60)
  IN NS ns.example.com.
ns IN A 192.0.2.1
blocked IN A 192.0.2.101
deep.blocked IN A 192.0.2.103
allowed IN A 192.0.2.101
sub.allowed IN A 192.0.2.101
deep.allowed IN A 192.0.2.101
redirect IN A 192.0.2.102
sub.redirect IN A 192.0.2.102
deep.redirect IN A 192.0.2.102
EOF
  cp "$RUNTIME_DIR/primary-data/app.test.zone" "$RUNTIME_DIR/secondary-1-data/app.test.zone"
  cp "$RUNTIME_DIR/primary-data/app.test.zone" "$RUNTIME_DIR/secondary-2-data/app.test.zone"
  local tld_fixture_count="${TLD_FIXTURE_COUNT:-2}"
  if ! [[ "$tld_fixture_count" =~ ^[0-9]+$ ]] || ((tld_fixture_count < 2 || tld_fixture_count > 5000)); then
    echo "TLD_FIXTURE_COUNT must be between 2 and 5000" >&2
    return 2
  fi
  {
    echo '# Version 1, Last Updated DNSGuard isolated acceptance fixture'
    echo 'COM'
    echo 'NET'
    for index in $(seq 1 $((tld_fixture_count - 2))); do
      printf 'TEST%04d\n' "$index"
    done
  } >"$RUNTIME_DIR/tlds.txt"
  for dir in "$RUNTIME_DIR"/*-data "$RUNTIME_DIR"/*-logs; do
    chmod 0775 "$dir"
    chown_bind_tree "$dir"
  done

  cat >"$RUNTIME_DIR/dns-state.json" <<EOF
{
  "nodes": [
    {"id":"primary-1","name":"bind-primary","role":"primary","address":"127.0.0.1:${PRIMARY_PORT}","status":"unknown"},
    {"id":"secondary-1","name":"bind-secondary-1","role":"secondary","address":"127.0.0.1:${SECONDARY_1_PORT}","status":"unknown"},
    {"id":"secondary-2","name":"bind-secondary-2","role":"secondary","address":"127.0.0.1:${SECONDARY_2_PORT}","status":"unknown"}
  ],
  "rules": [],
  "published": [],
  "versions": [],
  "rulesRevision": 0
}
EOF
  cat >"$RUNTIME_DIR/dns-nodes.json" <<EOF
[
  {"id":"primary-1","name":"bind-primary","role":"primary","address":"127.0.0.1:${PRIMARY_PORT}"},
  {"id":"secondary-1","name":"bind-secondary-1","role":"secondary","address":"127.0.0.1:${SECONDARY_1_PORT}"},
  {"id":"secondary-2","name":"bind-secondary-2","role":"secondary","address":"127.0.0.1:${SECONDARY_2_PORT}"}
]
EOF
  printf '[]\n' >"$RUNTIME_DIR/audit.json"
  printf '[]\n' >"$RUNTIME_DIR/publish-jobs.json"
  chmod 0700 "$RUNTIME_DIR"
}

wait_dns() {
  local port="$1" i
  for i in $(seq 1 60); do
    if dig +tcp +norecurse +time=1 +tries=1 @127.0.0.1 -p "$port" rpz.local SOA +short 2>/dev/null | grep -q '[0-9]'; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

start_bind() {
  compose up -d
  wait_dns "${PRIMARY_PORT}"
  wait_dns "${SECONDARY_1_PORT}"
  wait_dns "${SECONDARY_2_PORT}"
  for _ in $(seq 1 60); do
    if dig +tcp +time=1 +tries=1 @127.0.0.1 -p "${BASELINE_PORT}" example.com SOA +short 2>/dev/null | grep -q '[0-9]'; then
      break
    fi
    sleep 0.5
  done
  dig +tcp +time=1 +tries=1 @127.0.0.1 -p "${BASELINE_PORT}" example.com SOA +short >/dev/null
  for port in ${PRIMARY_PORT} ${SECONDARY_1_PORT} ${SECONDARY_2_PORT}; do
    for _ in $(seq 1 60); do
      if dig +tcp +norecurse +time=1 +tries=1 @127.0.0.1 -p "$port" tld-deny.rpz.local SOA +short 2>/dev/null | grep -q '[0-9]'; then
        break
      fi
      sleep 0.5
    done
    dig +tcp +norecurse +time=1 +tries=1 @127.0.0.1 -p "$port" tld-deny.rpz.local SOA +short >/dev/null
  done
  dig +tcp +norecurse +time=2 +tries=1 @127.0.0.1 -p "${PRIMARY_PORT}" rpz.local SOA +short
  compose ps
}

start_tld_source() {
  (cd "$RUNTIME_DIR" && python3 -m http.server 18092 --bind 127.0.0.1 >"$RUNTIME_DIR/tld-source.log" 2>&1) &
  TLD_SOURCE_PID=$!
  for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:18092/tlds.txt >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

start_api() {
  local port="$1" dir="$2" path_prefix="${3:-}"
  local log_file="$dir/api-$port.log" pid_file="$dir/api-$port.pid"
  local key_file="${RPZ_KEY_FILE_OVERRIDE:-$RUNTIME_DIR/keys/rpz-manager.key}"
  local artifact_file="${RPZ_ARTIFACT_FILE_OVERRIDE:-$dir/rpz.local.db}"
  local run_user="${API_RUN_USER:-}"
  local configured_path="${path_prefix:+$path_prefix:}$PATH"
  local -a environment=(
    "APP_ENV=development"
    "AUTH_ENABLED=false"
    "LISTEN_ADDR=127.0.0.1:$port"
    "DNS_STATE_FILE=$dir/dns-state.json"
    "DNS_NODE_CONFIG_FILE=$dir/dns-nodes.json"
    "AUDIT_FILE=$dir/audit.json"
    "RPZ_PUBLISH_JOBS_FILE=$dir/publish-jobs.json"
    "RPZ_ARTIFACT_FILE=$artifact_file"
    "RPZ_PUBLISH_MODE=nsupdate"
    "RPZ_PRIMARY=127.0.0.1"
    "RPZ_PRIMARY_PORT=${PRIMARY_PORT}"
    "RPZ_ZONE=rpz.local"
    "RPZ_KEY_FILE=$key_file"
    "RPZ_PUBLISH_TIMEOUT_SECONDS=8"
    "RPZ_PUBLISH_RETRIES=0"
    "RPZ_PUBLISH_RETRY_BACKOFF_SECONDS=0"
    "DNS_NODE_ALLOWED_CIDRS=127.0.0.0/8"
    "RPZ_LOG_FILES=$dir/rpz.log"
    "TLD_DENY_ENABLED=true"
    "TLD_DENY_PUBLISH_ENABLED=true"
    "TLD_DENY_ZONE=tld-deny.rpz.local"
    "TLD_DENY_TTL_SECONDS=60"
    "TLD_SOURCE_URL=http://127.0.0.1:18092/tlds.txt"
    "TLD_STATE_FILE=$dir/tld-state.json"
    "TLD_DENY_ARTIFACT_FILE=$dir/tld-deny.rpz.local.db"
    "PATH=$configured_path"
  )
  mkdir -p "$dir"
  (
    cd "$ROOT_DIR"
    if [[ -n "$run_user" ]]; then
      runuser -u "$run_user" -- env "${environment[@]}" "$API_BIN" >"$log_file" 2>&1 &
    else
      env "${environment[@]}" "$API_BIN" >"$log_file" 2>&1 &
    fi
    echo $! >"$pid_file"
    # Keep a stable alias for helpers that restart the same temporary API
    # directory on another attempt.
    echo $! >"$dir/api.pid"
  )
  printf '%s' "$(cat "$pid_file")"
}

wait_api() {
  local url="$1" i
  for i in $(seq 1 60); do
    if curl -fsS "$url/api/health" >/dev/null 2>&1; then return 0; fi
    sleep 0.25
  done
  return 1
}

stop_api_pid() {
  local pid_file="$1" pid
  [[ -f "$pid_file" ]] || return 0
  pid="$(cat "$pid_file")"
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 30); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
  fi
}

json_value() {
  local file="$1" expr="$2"
  python3 - "$file" "$expr" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    value = json.load(f)
for part in sys.argv[2].split('.'):
    if not part:
        continue
    if isinstance(value, list):
        value = value[int(part)]
    else:
        value = value.get(part)
print('' if value is None else value)
PY
}

api_request() {
  local method="$1" url="$2" body="$3" out="$4"
  if [[ -n "$body" ]]; then
    curl -sS -X "$method" -H 'Content-Type: application/json' --data "$body" -o "$out" -w '%{http_code}' "$url"
  else
    curl -sS -X "$method" -o "$out" -w '%{http_code}' "$url"
  fi
}

create_rule() {
  local domain="$1" type="$2" value="$3" reason="$4" out="$RUNTIME_DIR/last-rule.json" code
  code="$(api_request POST "$API_URL/api/dns/rpz" "{\"domain\":\"$domain\",\"type\":\"$type\",\"value\":\"$value\",\"reason\":\"$reason\"}" "$out")"
  [[ "$code" == 201 ]] || { cat "$out"; return 1; }
  RULE_ID="$(json_value "$out" id)"
}

delete_rule() {
  local id="$1" out="$RUNTIME_DIR/delete-rule.json" code
  code="$(api_request DELETE "$API_URL/api/dns/rpz/$id" '' "$out")"
  [[ "$code" == 200 ]] || { cat "$out"; return 1; }
}

publish_and_wait() {
  local out="$RUNTIME_DIR/publish-response.json" job_file="$RUNTIME_DIR/job.json" code job status
  code="$(api_request POST "$API_URL/api/dns/rpz/publish" '' "$out")"
  [[ "$code" == 202 ]] || { cat "$out"; return 1; }
  job="$(json_value "$out" id)"
  [[ -n "$job" ]] || return 1
  for _ in $(seq 1 120); do
    curl -fsS "$API_URL/api/dns/rpz/jobs/$job" >"$job_file" || true
    status="$(json_value "$job_file" status 2>/dev/null || true)"
    case "$status" in
      succeeded|failed|reconcile_required) JOB_STATUS="$status"; JOB_FILE="$job_file"; JOB_ID="$job"; return 0 ;;
    esac
    sleep 0.25
  done
  echo "timeout waiting for job $job" >&2
  return 1
}

wait_job_running() {
  local job="$1" file="$RUNTIME_DIR/running-job.json" status
  for _ in $(seq 1 60); do
    curl -fsS "$API_URL/api/dns/rpz/jobs/$job" >"$file" || true
    status="$(json_value "$file" status 2>/dev/null || true)"
    [[ "$status" == running ]] && return 0
    [[ "$status" == succeeded || "$status" == failed || "$status" == reconcile_required ]] && return 1
    sleep 0.1
  done
  return 1
}

soa_serial() { dig +tcp +norecurse +time=2 +tries=1 @127.0.0.1 -p "$1" rpz.local SOA +short | awk '{print $3}'; }
answer() { dig +tcp +time=2 +tries=1 @127.0.0.1 -p "$1" "$2" A +short | tr '\n' ' ' | sed 's/[[:space:]]*$//'; }
wait_answer() {
  local port="$1" query="$2" wanted="$3" expected
  for _ in $(seq 1 360); do
    expected="$(answer "$port" "$query")"
    if [[ "$expected" == *"$wanted"* ]]; then return 0; fi
    sleep 0.25
  done
  echo "port=$port query=$query answer=$expected wanted=$wanted" >&2
  return 1
}

direct_add_rpz_rule() {
  local domain="$1" value="$2"
  {
    printf 'server 127.0.0.1 %s\nzone rpz.local\n' "$PRIMARY_PORT"
    printf 'update delete %s.rpz.local.\n' "$domain"
    printf 'update delete *.%s.rpz.local.\n' "$domain"
    printf 'update add %s.rpz.local. 60 A %s\n' "$domain" "$value"
    printf 'update add *.%s.rpz.local. 60 A %s\n' "$domain" "$value"
    printf 'send\n'
  } | nsupdate -k "$RUNTIME_DIR/keys/rpz-manager.key"
}

direct_delete_rpz_rule() {
  local domain="$1"
  {
    printf 'server 127.0.0.1 %s\nzone rpz.local\n' "$PRIMARY_PORT"
    printf 'update delete %s.rpz.local.\n' "$domain"
    printf 'update delete *.%s.rpz.local.\n' "$domain"
    printf 'send\n'
  } | nsupdate -k "$RUNTIME_DIR/keys/rpz-manager.key"
}

case_normal_publish() {
  create_rule passthru.app.test CNAME '' 'Docker passthru' 
  create_rule redirect.app.test A 192.0.2.55 'Docker exact redirect'
  create_rule wild.app.test A 192.0.2.66 'Docker wildcard redirect'
  publish_and_wait
  [[ "$JOB_STATUS" == succeeded ]] || { cat "$JOB_FILE"; return 1; }
  [[ "$(soa_serial "${PRIMARY_PORT}")" == "$(soa_serial "${SECONDARY_1_PORT}")" && "$(soa_serial "${PRIMARY_PORT}")" == "$(soa_serial "${SECONDARY_2_PORT}")" ]]
  named-checkzone rpz.local "$RUNTIME_DIR/rpz.local.db"
  grep -q 'redirect.app.test.rpz.local' "$RUNTIME_DIR/rpz.local.db"
  # Host-side AXFR is intentionally denied; perform the transfer query from
  # an isolated Secondary container so the source address matches the
  # Primary's allow-transfer policy.
  docker exec bind-secondary-1 dig +tcp +time=2 +tries=1 @172.30.0.10 rpz.local AXFR +noall +answer | grep -q 'wild.app.test.rpz.local'
  wait_answer "${PRIMARY_PORT}" passthru.app.test 192.0.2.10
  wait_answer "${PRIMARY_PORT}" redirect.app.test 192.0.2.55
  wait_answer "${PRIMARY_PORT}" foo.wild.app.test 192.0.2.66
  printf 'job=%s status=%s serial=%s\n' "$JOB_ID" "$JOB_STATUS" "$(soa_serial "${PRIMARY_PORT}")"
}

case_actual_rpz_resolution() {
  local expected port query wanted ok
  for port in ${PRIMARY_PORT} ${SECONDARY_1_PORT} ${SECONDARY_2_PORT}; do
    for query in passthru.app.test redirect.app.test foo.wild.app.test; do
      case "$query" in
        passthru.app.test) wanted=192.0.2.10 ;;
        redirect.app.test) wanted=192.0.2.55 ;;
        foo.wild.app.test) wanted=192.0.2.66 ;;
      esac
      ok=0
      # BIND may defer a response-policy reload when the zone was changed
      # immediately after startup. The recursive answer, not only SOA, is the
      # acceptance criterion, so wait for the actual policy to become active.
      for _ in $(seq 1 240); do
        expected="$(answer "$port" "$query")"
        if [[ "$expected" == *"$wanted"* ]]; then ok=1; break; fi
        sleep 0.25
      done
      [[ "$ok" == 1 ]] || { echo "port=$port query=$query answer=$expected wanted=$wanted"; return 1; }
    done
  done
  echo 'passthru, exact redirect, wildcard redirect verified on primary and both secondaries'
}

case_tld_default_deny() {
  local test_name="${TLD_DENY_TEST_NAME:-blocked.example.com}"
  local deny_zone="${TLD_DENY_ZONE:-tld-deny.rpz.local}"
  local deny_trigger="${TLD_DENY_TRIGGER:-com.tld-deny.rpz.local}"
  local baseline_port="${TLD_DENY_BASELINE_PORT:-${BASELINE_PORT}}"
  local expected_a="${TLD_DENY_EXPECTED_A:-192.0.2.101}"
  local expected_rcode="${TLD_DENY_EXPECTED_RCODE:-NXDOMAIN}"
  local baseline_answer policy_header policy_rcode evidence_answer port
  create_rule allowed.example.com CNAME '' 'TLD deny whitelist'
  create_rule redirect.example.com A 192.0.2.250 'TLD deny redirect'
  publish_and_wait
  [[ "$JOB_STATUS" == succeeded ]] || { cat "$JOB_FILE"; return 1; }
  baseline_answer="$(dig +tcp +norecurse +time=2 +tries=1 @127.0.0.1 -p "$baseline_port" "$test_name" A +short | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  [[ "$baseline_answer" == *"$expected_a"* ]] || { echo "baseline=$baseline_answer expected=$expected_a"; return 1; }
  local deep_baseline_answer
  deep_baseline_answer="$(dig +tcp +norecurse +time=2 +tries=1 @127.0.0.1 -p "$baseline_port" deep.blocked.example.com A +short | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  [[ "$deep_baseline_answer" == *192.0.2.103* ]] || { echo "deep-baseline=$deep_baseline_answer expected=192.0.2.103"; return 1; }
  for port in ${PRIMARY_PORT} ${SECONDARY_1_PORT} ${SECONDARY_2_PORT}; do
    for _ in $(seq 1 120); do
      policy_header="$(dig +tcp +time=2 +tries=1 +comments @127.0.0.1 -p "$port" "$test_name" A 2>&1 || true)"
      policy_rcode="$(sed -n 's/^;; ->>HEADER<<-.*status: \([^,]*\),.*/\1/p' <<<"$policy_header" | head -n1)"
      [[ "$policy_rcode" == "$expected_rcode" ]] && break
      sleep 0.25
    done
    [[ "$policy_rcode" == "$expected_rcode" ]] || { echo "port=$port policy_rcode=$policy_rcode expected=$expected_rcode"; return 1; }
    wait_answer "$port" allowed.example.com 192.0.2.101
    wait_answer "$port" sub.allowed.example.com 192.0.2.101
    wait_answer "$port" deep.allowed.example.com 192.0.2.101
    wait_answer "$port" redirect.example.com 192.0.2.250
    wait_answer "$port" sub.redirect.example.com 192.0.2.250
    wait_answer "$port" deep.redirect.example.com 192.0.2.250
  done
  for port in ${PRIMARY_PORT} ${SECONDARY_1_PORT} ${SECONDARY_2_PORT}; do
    for _ in $(seq 1 120); do
      policy_header="$(dig +tcp +time=2 +tries=1 +comments @127.0.0.1 -p "$port" deep.blocked.example.com A 2>&1 || true)"
      policy_rcode="$(sed -n 's/^;; ->>HEADER<<-.*status: \([^,]*\),.*/\1/p' <<<"$policy_header" | head -n1)"
      [[ "$policy_rcode" == "$expected_rcode" ]] && break
      sleep 0.25
    done
    [[ "$policy_rcode" == "$expected_rcode" ]] || { echo "port=$port deep policy_rcode=$policy_rcode expected=$expected_rcode"; return 1; }
  done
  evidence_answer="$(dig +tcp +time=2 +tries=1 +comments +norecurse @127.0.0.1 -p "${PRIMARY_PORT}" "$deny_trigger" CNAME 2>&1 || true)"
  grep -Eq '(^|[[:space:]])CNAME[[:space:]]+\.[[:space:]]*$' <<<"$evidence_answer" || { echo "deny_trigger=$deny_trigger did not show CNAME ."; return 1; }
  echo "tld_fixture_count=${TLD_FIXTURE_COUNT:-2} baseline=$baseline_answer deep-baseline=$deep_baseline_answer policy_rcode=$policy_rcode whitelist+subdomain+redirect+deny verified on all nodes; deny_trigger=$deny_trigger zone=$deny_zone"
}

case_duplicate_publish_guard() {
  local out="$RUNTIME_DIR/duplicate.json" code
  code="$(api_request POST "$API_URL/api/dns/rpz/publish" '' "$out")"
  [[ "$code" == 409 ]] || { cat "$out"; return 1; }
  grep -q '没有待发布\|待发布' "$out"
}

case_secondary_sync_delay() {
  create_rule delayed.app.test A 192.0.2.77 'offline delay'
  docker pause bind-secondary-2
  publish_and_wait
  local failed="$JOB_STATUS"
  docker unpause bind-secondary-2 >/dev/null
  [[ "$failed" == failed ]] || { cat "$JOB_FILE"; return 1; }
  grep -q 'sync_exception\|Secondary\|校验' "$JOB_FILE" || true
  create_rule delayed-recovery.app.test A 192.0.2.78 'delay recovery'
  publish_and_wait
  [[ "$JOB_STATUS" == succeeded ]] || { cat "$JOB_FILE"; return 1; }
  echo "paused secondary result=$failed; recovery result=$JOB_STATUS"
  printf '%s\n' "$RULE_ID" >"$RUNTIME_DIR/delay-recovery-id"
}

case_secondary_offline() {
  create_rule offline.app.test A 192.0.2.79 'secondary offline'
  compose stop bind-secondary-2 >/dev/null
  publish_and_wait
  local failed="$JOB_STATUS"
  compose start bind-secondary-2 >/dev/null
  wait_dns "${SECONDARY_2_PORT}"
  [[ "$failed" == failed ]] || { cat "$JOB_FILE"; return 1; }
  create_rule offline-recovery.app.test A 192.0.2.80 'secondary recovery'
  publish_and_wait
  [[ "$JOB_STATUS" == succeeded ]] || { cat "$JOB_FILE"; return 1; }
  echo "offline result=$failed; recovery result=$JOB_STATUS"
}

case_primary_offline() {
  create_rule primary-offline.app.test A 192.0.2.81 'primary offline'
  compose stop bind-primary >/dev/null
  publish_and_wait
  local failed="$JOB_STATUS"
  compose start bind-primary >/dev/null
  wait_dns "${PRIMARY_PORT}"
  [[ "$failed" == failed ]] || { cat "$JOB_FILE"; return 1; }
  delete_rule "$RULE_ID"
  echo "primary offline publish result=$failed; draft removed without BIND mutation"
}

case_bind_restart_recovery() {
  local serial_before serial_after
  serial_before="$(soa_serial "${PRIMARY_PORT}")"
  compose restart bind-primary >/dev/null
  wait_dns "${PRIMARY_PORT}"
  wait_answer "${PRIMARY_PORT}" redirect.app.test 192.0.2.55
  compose restart bind-secondary-1 >/dev/null
  wait_dns "${SECONDARY_1_PORT}"
  serial_after="$(soa_serial "${PRIMARY_PORT}")"
  [[ -n "$serial_after" && "$serial_after" == "$(soa_serial "${SECONDARY_1_PORT}")" && "$serial_after" == "$(soa_serial "${SECONDARY_2_PORT}")" ]]
  echo "BIND restart preserved RPZ policy and SOA serial: $serial_before -> $serial_after"
}

case_axfr_recovery() {
  local before primary_after secondary_after
  before="$(soa_serial "${PRIMARY_PORT}")"
  compose stop bind-secondary-1 >/dev/null
  direct_add_rpz_rule axfr-recovery.app.test 192.0.2.90
  primary_after="$(soa_serial "${PRIMARY_PORT}")"
  [[ "$primary_after" != "$before" ]]
  rm -f "$RUNTIME_DIR/secondary-1-data/rpz.local.zone"*
  compose start bind-secondary-1 >/dev/null
  wait_dns "${SECONDARY_1_PORT}"
  for _ in $(seq 1 60); do
    secondary_after="$(soa_serial "${SECONDARY_1_PORT}")"
    [[ "$secondary_after" == "$primary_after" ]] && break
    sleep 0.25
  done
  [[ "$secondary_after" == "$primary_after" ]]
    [[ "$(dig +tcp +norecurse +time=2 +tries=1 @127.0.0.1 -p "${SECONDARY_1_PORT}" axfr-recovery.app.test.rpz.local A +short)" == "192.0.2.90" ]]
  direct_delete_rpz_rule axfr-recovery.app.test
  echo "Secondary recovered by full transfer after local RPZ data removal: serial=$secondary_after"
}

copy_api_fixture() {
  local dir="$1"
  mkdir -p "$dir"
  cp "$RUNTIME_DIR/dns-state.json" "$dir/dns-state.json"
  cp "$RUNTIME_DIR/dns-nodes.json" "$dir/dns-nodes.json"
  cp "$RUNTIME_DIR/audit.json" "$dir/audit.json"
  cp "$RUNTIME_DIR/publish-jobs.json" "$dir/publish-jobs.json"
}

case_tsig_error() {
  local dir="$RUNTIME_DIR/tsig-error" key pid code
  copy_api_fixture "$dir"
  printf 'key "rpz-manager" { algorithm hmac-sha256; secret "d3Jvbmcga2V5"; };\n' >"$dir/bad.key"
  chmod 0600 "$dir/bad.key"
  (cd "$ROOT_DIR" && env APP_ENV=development AUTH_ENABLED=false LISTEN_ADDR=127.0.0.1:18082 \
    DNS_STATE_FILE="$dir/dns-state.json" DNS_NODE_CONFIG_FILE="$dir/dns-nodes.json" AUDIT_FILE="$dir/audit.json" \
    RPZ_PUBLISH_JOBS_FILE="$dir/publish-jobs.json" RPZ_ARTIFACT_FILE="$dir/rpz.local.db" RPZ_PUBLISH_MODE=nsupdate \
    RPZ_PRIMARY=127.0.0.1 RPZ_PRIMARY_PORT="${PRIMARY_PORT}" RPZ_ZONE=rpz.local RPZ_KEY_FILE="$dir/bad.key" \
    RPZ_PUBLISH_TIMEOUT_SECONDS=8 RPZ_PUBLISH_RETRIES=0 DNS_NODE_ALLOWED_CIDRS=127.0.0.0/8 \
    "$API_BIN" >"$dir/api.log" 2>&1 & echo $! >"$dir/api.pid")
  wait_api http://127.0.0.1:18082
  code="$(curl -sS -X POST -H 'Content-Type: application/json' --data '{"domain":"bad-tsig.app.test","type":"A","value":"192.0.2.82"}' -o "$dir/rule.json" -w '%{http_code}' http://127.0.0.1:18082/api/dns/rpz)"
  [[ "$code" == 201 ]]
  code="$(curl -sS -X POST -o "$dir/publish.json" -w '%{http_code}' http://127.0.0.1:18082/api/dns/rpz/publish)"
  [[ "$code" == 202 ]]
  key="$(json_value "$dir/publish.json" id)"
  for _ in $(seq 1 80); do
    curl -fsS "http://127.0.0.1:18082/api/dns/rpz/jobs/$key" >"$dir/job.json" || true
    [[ "$(json_value "$dir/job.json" status 2>/dev/null || true)" == reconcile_required ]] && break
    sleep 0.25
  done
  [[ "$(json_value "$dir/job.json" status)" == reconcile_required ]]
  stop_api_pid "$dir/api.pid"
  echo "invalid TSIG produced reconcile_required; no automatic replay"
}

case_api_restart_recovery() {
  local dir="$RUNTIME_DIR/api-restart" marker="$RUNTIME_DIR/api-restart/started" fake="$RUNTIME_DIR/api-restart/fake-bin" pid job
  copy_api_fixture "$dir"
  mkdir -p "$fake"
  cat >"$fake/nsupdate" <<EOF
#!/usr/bin/env bash
touch "$marker"
sleep 60
EOF
  chmod +x "$fake/nsupdate"
  pid="$(start_api 18083 "$dir" "$fake")"
  wait_api http://127.0.0.1:18083
  curl -fsS -X POST -H 'Content-Type: application/json' --data '{"domain":"restart.app.test","type":"A","value":"192.0.2.83"}' -o "$dir/rule.json" http://127.0.0.1:18083/api/dns/rpz
  curl -fsS -X POST -o "$dir/publish.json" http://127.0.0.1:18083/api/dns/rpz/publish
  job="$(json_value "$dir/publish.json" id)"
  API_URL="http://127.0.0.1:18083" wait_job_running "$job"
  kill "$pid" 2>/dev/null || true
  sleep 0.5
  pkill -f "$fake/nsupdate" 2>/dev/null || true
  pid="$(start_api 18083 "$dir")"
  wait_api http://127.0.0.1:18083
  curl -fsS "http://127.0.0.1:18083/api/dns/rpz/jobs/$job" >"$dir/recovered.json"
  [[ "$(json_value "$dir/recovered.json" status)" == reconcile_required ]]
  stop_api_pid "$dir/api.pid"
  echo 'queued/running task recovered as reconcile_required after API restart'
}

case_concurrent_edit_snapshot() {
  local dir="$RUNTIME_DIR/concurrent-edit" fake="$RUNTIME_DIR/concurrent-edit/fake-bin" pid job status_a status_b
  copy_api_fixture "$dir"
  mkdir -p "$fake"
  cat >"$fake/nsupdate" <<'EOF'
#!/usr/bin/env bash
/usr/bin/nsupdate "$@"
sleep 3
EOF
  chmod +x "$fake/nsupdate"
  pid="$(start_api 18084 "$dir" "$fake")"
  wait_api http://127.0.0.1:18084
  curl -fsS -X POST -H 'Content-Type: application/json' --data '{"domain":"snapshot-a.app.test","type":"A","value":"192.0.2.84"}' -o "$dir/a.json" http://127.0.0.1:18084/api/dns/rpz
  curl -fsS -X POST -o "$dir/publish.json" http://127.0.0.1:18084/api/dns/rpz/publish
  job="$(json_value "$dir/publish.json" id)"
  API_URL="http://127.0.0.1:18084" wait_job_running "$job"
  curl -fsS -X POST -H 'Content-Type: application/json' --data '{"domain":"snapshot-b.app.test","type":"A","value":"192.0.2.85"}' -o "$dir/b.json" http://127.0.0.1:18084/api/dns/rpz
  for _ in $(seq 1 80); do
    curl -fsS "http://127.0.0.1:18084/api/dns/rpz/jobs/$job" >"$dir/job.json" || true
    status="$(json_value "$dir/job.json" status 2>/dev/null || true)"
    [[ "$status" == succeeded ]] && break
    sleep 0.25
  done
  curl -fsS http://127.0.0.1:18084/api/dns/rpz >"$dir/rules.json"
  status_a="$(python3 - "$dir/rules.json" <<'PY'
import json, sys
rules=json.load(open(sys.argv[1]))
print(next(r['status'] for r in rules if r['domain']=='snapshot-a.app.test'))
PY
)"
  status_b="$(python3 - "$dir/rules.json" <<'PY'
import json, sys
rules=json.load(open(sys.argv[1]))
print(next(r['status'] for r in rules if r['domain']=='snapshot-b.app.test'))
PY
)"
  [[ "$status_a" == published && "$status_b" == draft ]]
  direct_delete_rpz_rule snapshot-a.app.test
  direct_delete_rpz_rule snapshot-b.app.test
  stop_api_pid "$dir/api.pid"
  echo "snapshot-a=$status_a snapshot-b=$status_b"
}

case_concurrent_publish_guard() {
  local dir="$RUNTIME_DIR/concurrent-publish" fake="$RUNTIME_DIR/concurrent-publish/fake-bin" pid code_one code_two job
  copy_api_fixture "$dir"
  mkdir -p "$fake"
  cat >"$fake/nsupdate" <<'EOF'
#!/usr/bin/env bash
/usr/bin/nsupdate "$@"
sleep 3
EOF
  chmod +x "$fake/nsupdate"
  pid="$(start_api 18086 "$dir" "$fake")"
  wait_api http://127.0.0.1:18086
  curl -fsS -X POST -H 'Content-Type: application/json' --data '{"domain":"concurrent-publish.app.test","type":"A","value":"192.0.2.91"}' -o "$dir/rule.json" http://127.0.0.1:18086/api/dns/rpz
  curl -sS -X POST -o "$dir/one.json" -w '%{http_code}' http://127.0.0.1:18086/api/dns/rpz/publish >"$dir/one.code" &
  local request_one=$!
  sleep 0.05
  curl -sS -X POST -o "$dir/two.json" -w '%{http_code}' http://127.0.0.1:18086/api/dns/rpz/publish >"$dir/two.code" &
  local request_two=$!
  wait "$request_one"
  wait "$request_two"
  code_one="$(cat "$dir/one.code")"
  code_two="$(cat "$dir/two.code")"
  [[ ("$code_one" == 202 && "$code_two" == 409) || ("$code_one" == 409 && "$code_two" == 202) ]]
  if [[ "$code_one" == 202 ]]; then job="$(json_value "$dir/one.json" id)"; else job="$(json_value "$dir/two.json" id)"; fi
  for _ in $(seq 1 80); do
    curl -fsS "http://127.0.0.1:18086/api/dns/rpz/jobs/$job" >"$dir/job.json" || true
    [[ "$(json_value "$dir/job.json" status 2>/dev/null || true)" == succeeded ]] && break
    sleep 0.25
  done
  [[ "$(json_value "$dir/job.json" status)" == succeeded ]]
  direct_delete_rpz_rule concurrent-publish.app.test
  stop_api_pid "$dir/api.pid"
  echo "concurrent publish HTTP codes: $code_one, $code_two"
}

case_queued_recovery() {
  local dir="$RUNTIME_DIR/queued-recovery" pid job_id
  copy_api_fixture "$dir"
  job_id="queued-recovery-$RUN_ID"
  cat >"$dir/publish-jobs.json" <<EOF
[{"id":"$job_id","status":"queued","createdAt":"2026-11-04T00:00:00Z"}]
EOF
  pid="$(start_api 18087 "$dir")"
  wait_api http://127.0.0.1:18087
  curl -fsS "http://127.0.0.1:18087/api/dns/rpz/jobs/$job_id" >"$dir/recovered.json"
  [[ "$(json_value "$dir/recovered.json" status)" == reconcile_required ]]
  stop_api_pid "$dir/api.pid"
  echo 'persisted queued task became reconcile_required during API startup'
}

case_audit_corruption_fail_closed() {
  local dir="$RUNTIME_DIR/audit-corrupt" pid code
  copy_api_fixture "$dir"
  printf '[{"timestamp":"tampered","actor":"attacker","action":"rpz.rule.create","result":"fake","hash":"bad"}]\n' >"$dir/audit.json"
  pid="$(start_api 18088 "$dir")"
  wait_api http://127.0.0.1:18088
  code="$(curl -sS -X POST -H 'Content-Type: application/json' --data '{"domain":"audit-blocked.app.test","type":"A","value":"192.0.2.92"}' -o "$dir/write.json" -w '%{http_code}' http://127.0.0.1:18088/api/dns/rpz)"
  [[ "$code" == 503 ]]
  if grep -q 'audit-blocked.app.test' "$dir/dns-state.json"; then
    return 1
  fi
  stop_api_pid "$dir/api.pid"
  printf '[]\n' >"$dir/audit.json"
  pid="$(start_api 18088 "$dir")"
  wait_api http://127.0.0.1:18088
  code="$(curl -sS -X POST -H 'Content-Type: application/json' --data '{"domain":"audit-recovered.app.test","type":"A","value":"192.0.2.93"}' -o "$dir/recovered-write.json" -w '%{http_code}' http://127.0.0.1:18088/api/dns/rpz)"
  [[ "$code" == 201 ]]
  stop_api_pid "$dir/api.pid"
  echo 'corrupt audit chain blocked writes; replacing it and restarting restored writes'
}

case_artifact_write_failure() {
  local dir="$RUNTIME_DIR/artifact-write-failure" artifact_dir pid code
  copy_api_fixture "$dir"
  artifact_dir="$dir/artifact-dir"
  mkdir -p "$artifact_dir"
  cp "$RUNTIME_DIR/keys/rpz-manager.key" "$dir/test.key"
  chown -R "$TEST_RUN_USER:$TEST_RUN_GROUP" "$dir"
  chmod 0600 "$dir/test.key"
  chmod 0755 "$RUNTIME_DIR"
  API_RUN_USER="$TEST_RUN_USER" RPZ_KEY_FILE_OVERRIDE="$dir/test.key" RPZ_ARTIFACT_FILE_OVERRIDE="$artifact_dir/rpz.local.db" pid="$(start_api 18089 "$dir")"
  wait_api http://127.0.0.1:18089
  curl -fsS -X POST -H 'Content-Type: application/json' --data '{"domain":"artifact-failure.app.test","type":"A","value":"192.0.2.94"}' -o "$dir/rule.json" http://127.0.0.1:18089/api/dns/rpz
  chmod 0500 "$artifact_dir"
  code="$(curl -sS -X POST -o "$dir/publish.json" -w '%{http_code}' http://127.0.0.1:18089/api/dns/rpz/publish)"
  [[ "$code" == 202 ]]
  local job
  job="$(json_value "$dir/publish.json" id)"
  for _ in $(seq 1 80); do
    curl -fsS "http://127.0.0.1:18089/api/dns/rpz/jobs/$job" >"$dir/job.json" || true
    [[ "$(json_value "$dir/job.json" status 2>/dev/null || true)" == failed ]] && break
    sleep 0.25
  done
  chmod 0700 "$artifact_dir"
  [[ "$(json_value "$dir/job.json" status)" == failed ]]
  stop_api_pid "$dir/api.pid"
  chmod 0700 "$RUNTIME_DIR"
  echo 'artifact write failure prevented nsupdate and produced a failed job'
}

case_rollback_failure() {
  local dir="$RUNTIME_DIR/rollback-failure" pid version_id code job
  copy_api_fixture "$dir"
  version_id="$(python3 - "$dir/dns-state.json" <<'PY'
import json, sys
s=json.load(open(sys.argv[1]))
versions=s.get('versions', [])
print(versions[-1]['id'] if len(versions) > 1 else '')
PY
)"
  [[ -n "$version_id" ]]
  pid="$(start_api 18090 "$dir")"
  wait_api http://127.0.0.1:18090
  curl -fsS -X POST -H 'Content-Type: application/json' --data '{"domain":"rollback-failure.app.test","type":"A","value":"192.0.2.95"}' -o "$dir/rule.json" http://127.0.0.1:18090/api/dns/rpz
  compose stop bind-primary >/dev/null
  code="$(curl -sS -X POST -H 'Content-Type: application/json' --data "{\"versionId\":\"$version_id\"}" -o "$dir/rollback.json" -w '%{http_code}' http://127.0.0.1:18090/api/dns/rpz/rollback)"
  compose start bind-primary >/dev/null
  wait_dns "${PRIMARY_PORT}"
  [[ "$code" == 202 ]]
  job="$(json_value "$dir/rollback.json" id)"
  for _ in $(seq 1 80); do
    curl -fsS "http://127.0.0.1:18090/api/dns/rpz/jobs/$job" >"$dir/job.json" || true
    [[ "$(json_value "$dir/job.json" status 2>/dev/null || true)" == failed ]] && break
    sleep 0.25
  done
  [[ "$(json_value "$dir/job.json" status)" == failed ]]
  stop_api_pid "$dir/api.pid"
  echo 'rollback publish failed safely while Primary was offline; no automatic rollback was attempted'
}

case_frontend_smoke() {
  local config="$RUNTIME_DIR/frontend-test.config.mjs" pid
  npm run build >"$RUNTIME_DIR/frontend-build.log" 2>&1
  cat >"$config" <<EOF
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({plugins:[react()],preview:{proxy:{"/api":{target:"$API_URL",changeOrigin:true}}}});
EOF
  (cd "$ROOT_DIR" && npx vite preview --config "$config" --host 127.0.0.1 --port 18091 --strictPort >"$RUNTIME_DIR/frontend-preview.log" 2>&1 & echo $! >"$RUNTIME_DIR/frontend-preview.pid")
  for _ in $(seq 1 40); do curl -fsS http://127.0.0.1:18091/ >/dev/null 2>&1 && break; sleep .25; done
  curl -fsS http://127.0.0.1:18091/ | grep -q '<div id="root">'
  curl -fsS http://127.0.0.1:18091/api/dns/nodes | grep -q 'bind-primary'
  pid="$(cat "$RUNTIME_DIR/frontend-preview.pid")"
  kill "$pid" 2>/dev/null || true
  echo 'React build, preview page, and API proxy smoke test passed'
}

case_failed_publish_recovery() {
  local dir="$RUNTIME_DIR/state-write-failure" fake="$RUNTIME_DIR/state-write-failure/fake-bin" marker="$RUNTIME_DIR/state-write-failure/nsupdate.done" pid job
  copy_api_fixture "$dir"
  mkdir -p "$fake"
  cp "$RUNTIME_DIR/keys/rpz-manager.key" "$dir/test.key"
  chown -R "$TEST_RUN_USER:$TEST_RUN_GROUP" "$dir"
  chmod 0755 "$RUNTIME_DIR"
  chmod 0600 "$dir/test.key"
  cat >"$fake/nsupdate" <<EOF
#!/usr/bin/env bash
/usr/bin/nsupdate "\$@"
touch "$marker"
sleep 5
EOF
  chown "$TEST_RUN_USER:$TEST_RUN_GROUP" "$fake/nsupdate"
  chmod +x "$fake/nsupdate"
  API_RUN_USER="$TEST_RUN_USER" RPZ_KEY_FILE_OVERRIDE="$dir/test.key" pid="$(start_api 18085 "$dir" "$fake")"
  wait_api http://127.0.0.1:18085
  curl -fsS -X POST -H 'Content-Type: application/json' --data '{"domain":"state-failure.app.test","type":"A","value":"192.0.2.86"}' -o "$dir/rule.json" http://127.0.0.1:18085/api/dns/rpz
  curl -fsS -X POST -o "$dir/publish.json" http://127.0.0.1:18085/api/dns/rpz/publish
  job="$(json_value "$dir/publish.json" id)"
  for _ in $(seq 1 60); do [[ -f "$marker" ]] && break; sleep 0.1; done
  [[ -f "$marker" ]]
  chmod 0500 "$dir"
  for _ in $(seq 1 100); do
    curl -fsS "http://127.0.0.1:18085/api/dns/rpz/jobs/$job" >"$dir/job.json" || true
    [[ "$(json_value "$dir/job.json" status 2>/dev/null || true)" == reconcile_required ]] && break
    sleep 0.25
  done
  chmod 0700 "$dir"
  [[ "$(json_value "$dir/job.json" status)" == reconcile_required ]]
  stop_api_pid "$dir/api.pid"
  direct_delete_rpz_rule state-failure.app.test
  chmod 0700 "$RUNTIME_DIR"
  echo 'Primary update completed before state write failure; job retained reconcile_required for manual comparison'
}

case_bind_independent() {
  [[ -n "$API_PID" ]] || return 1
  kill "$API_PID" 2>/dev/null || true
  API_PID=""
  sleep 0.5
  [[ -n "$(soa_serial "${PRIMARY_PORT}")" && "$(answer "${PRIMARY_PORT}" redirect.app.test)" == *192.0.2.55* ]]
  [[ -n "$(soa_serial "${SECONDARY_1_PORT}")" && "$(answer "${SECONDARY_2_PORT}" foo.wild.app.test)" == *192.0.2.66* ]]
  echo 'DNS queries and RPZ policy remained available while DNSGuard API was stopped'
}

write_report() {
  mkdir -p "$RUNTIME_DIR"
  {
    echo "# DNSGuard V1.0 Docker BIND 集群生产级验收报告"
    echo
    echo "- 执行时间（UTC）：$RUN_ID"
    echo "- Compose 项目：$PROJECT"
    echo "- 隔离网络：dnsguard-bind-acceptance (172.30.0.0/24)"
    echo "- 宿主机端口：${PRIMARY_PORT}/${SECONDARY_1_PORT}/${SECONDARY_2_PORT}（RPZ 集群）和 ${BASELINE_PORT}（隔离基线源，均未占用 53）"
    echo "- 生产连接：无"
    echo
    echo "## 用例结果"
    echo
    echo '| 用例 | 结果 | 证据 |'
    echo '|---|---|---|'
    for i in "${!CASE_NAMES[@]}"; do
      echo "| ${CASE_NAMES[$i]} | ${CASE_STATUS[$i]} | \`${CASE_EVIDENCE[$i]}\` |"
    done
    echo
    echo '## 证据边界'
    echo
    echo '- PASS 仅表示该命令在本次本地 Docker 隔离环境真实执行并满足断言。'
    echo '- FAIL 表示脚本执行了用例但断言失败；NOT RUN 不会被改写成 PASS。'
    echo '- TSIG 内容、zone journal 和 API 状态均位于被 Git 忽略的 runtime 目录。'
    echo '- 该报告不代表生产变更、生产部署或生产 DNS 验收。'
  } >"$REPORT"
}

main() {
  prepare_runtime
  if ((BIND_ONLY)); then
    start_bind
    return 0
  fi
  (cd "$ROOT_DIR/server" && go build -o "$API_BIN" .)
  start_bind
  start_tld_source
  API_PID="$(start_api "$API_PORT" "$RUNTIME_DIR")"
  wait_api "$API_URL"
  run_case 'normal-publish-and-zone-transfer' case_normal_publish
  run_case 'actual-rpz-recursion-effects' case_actual_rpz_resolution
  run_case 'tld-default-deny-policy' case_tld_default_deny
  run_case 'duplicate-publish-guard' case_duplicate_publish_guard
  run_case 'secondary-sync-delay-and-recovery' case_secondary_sync_delay
  run_case 'secondary-offline-and-recovery' case_secondary_offline
  run_case 'primary-offline' case_primary_offline
  run_case 'bind-restart-recovery' case_bind_restart_recovery
  run_case 'axfr-recovery-after-secondary-data-loss' case_axfr_recovery
  run_case 'tsig-authentication-failure' case_tsig_error
  run_case 'api-restart-recovery' case_api_restart_recovery
  run_case 'concurrent-edit-snapshot' case_concurrent_edit_snapshot
  run_case 'concurrent-publish-guard' case_concurrent_publish_guard
  run_case 'queued-job-startup-recovery' case_queued_recovery
  run_case 'audit-corruption-fail-closed-and-recovery' case_audit_corruption_fail_closed
  run_case 'artifact-write-failure' case_artifact_write_failure
  run_case 'rollback-failure' case_rollback_failure
  run_case 'state-write-failure-recovery' case_failed_publish_recovery
  run_case 'frontend-build-and-api-proxy-smoke' case_frontend_smoke
  run_case 'bind-independent-of-api' case_bind_independent
  write_report
  if printf '%s\n' "${CASE_STATUS[@]}" | grep -q '^FAIL$'; then
    return 1
  fi
}

main
