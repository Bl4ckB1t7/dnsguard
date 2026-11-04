#!/usr/bin/env bash
# DNSGuard BIND RPZ read-only preflight and explicitly confirmed TSIG test.
set -Eeuo pipefail
shopt -s extglob

SCRIPT_NAME="$(basename "$0")"
RPZ_ZONE="${RPZ_ZONE-}"
RPZ_PRIMARY="${RPZ_PRIMARY-}"
RPZ_PRIMARY_PORT="${RPZ_PRIMARY_PORT-}"
RPZ_SECONDARIES="${RPZ_SECONDARIES-}"
RPZ_KEY_FILE="${RPZ_KEY_FILE-}"
RPZ_RECURSOR="${RPZ_RECURSOR-}"
RPZ_TEST_DOMAIN="${RPZ_TEST_DOMAIN-}"
RPZ_TEST_NAMESPACE="${RPZ_TEST_NAMESPACE-}"
RPZ_CHECK_NAME="${RPZ_CHECK_NAME-}"
RPZ_EXPECTED_A="${RPZ_EXPECTED_A-}"
ENV_FILE="${RPZ_CONNECT_ENV_FILE-}"
OUTPUT_DIR=""
WRITE_TEST=0
CONFIRM_WRITE="${RPZ_CONNECT_CONFIRM-}"
FAILURES=0
WARNINGS=0
PRIMARY_SERIAL=""
TEST_RECORD_NEEDS_CLEANUP=0
TEST_INPUT_FILES=()
DNS_QUERY_STATE=""
DNS_QUERY_OUTPUT=""
EXACT_QUERY_STATE=""

usage() {
  cat <<USAGE
Usage: $SCRIPT_NAME [options]

Read-only preflight (default):
  $SCRIPT_NAME --env-file deploy/docker/rpz-connect.env

Options:
  --env-file FILE     Read only RPZ_CONNECT_* values from FILE. Shell code is not executed.
  --zone NAME         RPZ zone name.
  --primary HOST[:P]  RPZ Primary host or address.
  --primary-port P    RPZ Primary port when --primary has no port (default: 53).
  --secondaries LIST  Comma-separated Secondary endpoints, e.g. HOST1:53,HOST2:53.
  --key-file FILE     Host path to the TSIG key used by nsupdate.
  --render DIR        Render safe config templates into DIR; never writes BIND files.
  --write-test        Explicitly write/delete one temporary TXT record on Primary.
  --test-domain NAME  Optional test name below the protected test namespace.
  --test-namespace NAME  Protected namespace for custom test names.
  --confirm VALUE     Non-interactive confirmation; VALUE must be WRITE-TEST.
  -h, --help          Show this help.

The script never edits named.conf, reloads BIND, publishes RPZ rules, or changes
Docker Compose state. --write-test is the only mode that changes a Zone, and it
cleans up the temporary record before returning.
USAGE
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  FAILURES=$((FAILURES + 1))
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
  WARNINGS=$((WARNINGS + 1))
}

pass() {
  printf 'PASS: %s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || { fail "缺少命令: $1"; return 1; }
}

# Read only known KEY=VALUE lines. Values are not evaluated as shell code.
load_env_file() {
  local key value line
  [[ -f "$ENV_FILE" ]] || { fail "配置文件不存在: $ENV_FILE"; return; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      value="${BASH_REMATCH[2]}"
      value="${value#\"}"
      value="${value%\"}"
      case "$key" in
        RPZ_ZONE|RPZ_PRIMARY|RPZ_PRIMARY_PORT|RPZ_SECONDARIES|RPZ_KEY_FILE|RPZ_RECURSOR|RPZ_TEST_DOMAIN|RPZ_TEST_NAMESPACE|RPZ_WRITE_TIMEOUT_SECONDS|RPZ_CHECK_NAME|RPZ_EXPECTED_A)
          # Explicit environment variables take precedence over the file.
          if [[ -z "${!key+x}" || -z "${!key}" ]]; then
            printf -v "$key" '%s' "$value"
          fi
          ;;
      esac
    fi
  done < "$ENV_FILE"
}

parse_endpoint() {
  local endpoint="$1" default_port="${2:-53}"
  if [[ "$endpoint" =~ ^\[([^]]+)\](:([0-9]+))?$ ]]; then
    ENDPOINT_HOST="${BASH_REMATCH[1]}"
    ENDPOINT_PORT="${BASH_REMATCH[3]:-$default_port}"
  elif [[ "$endpoint" =~ ^(.+):([0-9]+)$ ]]; then
    ENDPOINT_HOST="${BASH_REMATCH[1]}"
    ENDPOINT_PORT="${BASH_REMATCH[2]}"
  else
    ENDPOINT_HOST="$endpoint"
    ENDPOINT_PORT="$default_port"
  fi
  if [[ -z "$ENDPOINT_HOST" || ! "$ENDPOINT_PORT" =~ ^[0-9]+$ ]] || ((ENDPOINT_PORT < 1 || ENDPOINT_PORT > 65535)); then
    return 1
  fi
}

soa_serial() {
  local host="$1" port="$2" proto="$3" output
  local -a args=(+short +time=2 +tries=1 "@$host" -p "$port" "$RPZ_ZONE" SOA)
  [[ "$proto" == tcp ]] && args=(+tcp "${args[@]}")
  output="$(dig "${args[@]}" 2>/dev/null || true)"
  awk 'NF >= 3 && $3 ~ /^[0-9]+$/ { print $3; exit }' <<<"$output"
}

check_endpoint() {
  local label="$1" endpoint="$2" default_port="${3:-53}" serial_udp serial_tcp
  parse_endpoint "$endpoint" "$default_port" || { fail "$label 地址无效: $endpoint"; return; }
  serial_udp="$(soa_serial "$ENDPOINT_HOST" "$ENDPOINT_PORT" udp)"
  serial_tcp="$(soa_serial "$ENDPOINT_HOST" "$ENDPOINT_PORT" tcp)"
  if [[ -z "$serial_udp" && -z "$serial_tcp" ]]; then
    fail "$label 无法读取 $RPZ_ZONE SOA: $endpoint"
    return
  fi
  if [[ -n "$serial_udp" && -n "$serial_tcp" && "$serial_udp" != "$serial_tcp" ]]; then
    fail "$label UDP/TCP SOA Serial 不一致: $endpoint"
    return
  fi
  local serial="${serial_tcp:-$serial_udp}"
  pass "$label 可达，SOA Serial=$serial ($endpoint)"
  if [[ "$label" == Primary ]]; then
    PRIMARY_SERIAL="$serial"
  elif [[ -n "$PRIMARY_SERIAL" && "$serial" != "$PRIMARY_SERIAL" ]]; then
    fail "$label Serial=$serial，与 Primary=$PRIMARY_SERIAL 不一致"
  fi
}

check_key() {
  [[ -n "$RPZ_KEY_FILE" ]] || { fail '未配置 RPZ_KEY_FILE；无法进行 TSIG 对接检查'; return; }
  [[ ! -L "$RPZ_KEY_FILE" ]] || { fail 'TSIG 文件不能是符号链接'; return; }
  [[ -f "$RPZ_KEY_FILE" ]] || { fail "TSIG 文件不存在: $RPZ_KEY_FILE"; return; }
  [[ -r "$RPZ_KEY_FILE" ]] || { fail '当前执行用户无法读取 TSIG 文件'; return; }
  local mode
  mode="$(stat -c '%a' "$RPZ_KEY_FILE" 2>/dev/null || true)"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || { fail '无法读取 TSIG 文件权限'; return; }
  local numeric=$((8#$mode))
  if ((numeric & 7)); then
    fail "TSIG 文件对其他用户可读或可写，当前权限=$mode；应收紧到不含 other 权限"
    return
  fi
  pass "TSIG 文件存在且权限未向 other 开放（$mode）"
}

render_templates() {
  [[ -n "$OUTPUT_DIR" ]] || return 0
  mkdir -p "$OUTPUT_DIR"
  umask 077
  cat >"$OUTPUT_DIR/dnsguard-rpz.env" <<TEMPLATE
# Generated by $SCRIPT_NAME. Review before use; no secret is included.
RPZ_PUBLISH_MODE=nsupdate
RPZ_ZONE=${RPZ_ZONE:-RPZ_ZONE}
RPZ_PRIMARY=${RPZ_PRIMARY:-PRIMARY_IP}
RPZ_PRIMARY_PORT=${RPZ_PRIMARY_PORT:-53}
RPZ_KEY_FILE=/run/dnsguard-secrets/rpz-manager.key
TEMPLATE
  cat >"$OUTPUT_DIR/primary-rpz.conf" <<'TEMPLATE'
// Replace placeholders. This file is a template only; it is not installed by DNSGuard.
include "/etc/bind/keys/dnsguard-rpz.key";
zone "RPZ_ZONE" {
    type primary;
    file "/var/lib/bind/db.RPZ_ZONE";
    update-policy { grant dnsguard-rpz zonesub ANY; };
    notify yes;
    also-notify { SECONDARY_1_IP; SECONDARY_2_IP; };
    allow-transfer { SECONDARY_1_IP; SECONDARY_2_IP; };
};
TEMPLATE
  cat >"$OUTPUT_DIR/secondary-rpz.conf" <<'TEMPLATE'
// Replace placeholders. Add one zone block to each Secondary.
zone "RPZ_ZONE" {
    type secondary;
    primaries { PRIMARY_IP; };
    file "/var/cache/bind/db.RPZ_ZONE";
    allow-notify { PRIMARY_IP; };
};
TEMPLATE
  pass "已生成安全模板（不含 TSIG secret）: $OUTPUT_DIR"
}

test_domain_scope() {
  [[ "$WRITE_TEST" -eq 1 ]] || return 0
  local namespace name zone_base
  zone_base="${RPZ_ZONE%.}"
  namespace="${RPZ_TEST_NAMESPACE:-_dnsguard-preflight.${zone_base}}"
  namespace="${namespace%.}"
  name="${RPZ_TEST_DOMAIN:-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n').${namespace}}"
  name="${name%.}"
  valid_dns_name "$namespace" || { fail 'RPZ_TEST_NAMESPACE 格式无效'; return; }
  valid_dns_name "$name" || { fail '临时测试域名格式无效'; return; }
  if [[ -n "$RPZ_TEST_DOMAIN" && "$name" != *."$namespace" ]]; then
    fail "自定义测试域名必须位于测试命名空间 ${namespace} 下"
    return
  fi
  TEST_DOMAIN="${name}."
  TEST_NAMESPACE="${namespace}."
  pass "写入目标已限制在测试命名空间: $TEST_DOMAIN"
}

valid_dns_name() {
  local name="$1" label
  [[ -n "$name" && ${#name} -le 253 && "$name" != .* && "$name" != *..* ]] || return 1
  IFS='.' read -r -a labels <<<"$name"
  for label in "${labels[@]}"; do
    [[ -n "$label" && ${#label} -le 63 && "$label" =~ ^[A-Za-z0-9_][A-Za-z0-9_-]*[A-Za-z0-9_]$|^[A-Za-z0-9_]$ ]] || return 1
  done
}

query_record_state() {
  local host="$1" port="$2" name="$3" type="$4" output rcode flags answer
  DNS_QUERY_STATE="UNKNOWN"
  DNS_QUERY_OUTPUT=""
  output="$(dig +comments +norecurse +time=2 +tries=1 "@$host" -p "$port" "$name" "$type" 2>/dev/null || true)"
  DNS_QUERY_OUTPUT="$output"
  rcode="$(sed -n 's/^;; ->>HEADER<<-.*status: \([^,]*\),.*/\1/p' <<<"$output" | head -n1)"
  flags="$(sed -n 's/^;; flags: \([^;]*\);.*/\1/p' <<<"$output" | head -n1)"
  if [[ -z "$rcode" || "$flags" != *" aa"* ]]; then
    return 0
  fi
  case "$rcode" in
    NXDOMAIN)
      DNS_QUERY_STATE="NXDOMAIN"
      ;;
    NOERROR)
      answer="$(awk '!/^;;/ && NF >= 4 {found=1} END {if (found) print "PRESENT"}' <<<"$output")"
      DNS_QUERY_STATE="${answer:-NODATA}"
      ;;
    *)
      DNS_QUERY_STATE="UNKNOWN"
      ;;
  esac
}

record_exists() {
  query_record_state "$1" "$2" "$3" ANY
  [[ "$DNS_QUERY_STATE" == PRESENT ]]
}

exact_test_record_present() {
  local host="$1" port="$2" name="$3" token="$4"
  query_record_state "$host" "$port" "$name" TXT
  EXACT_QUERY_STATE="UNKNOWN"
  case "$DNS_QUERY_STATE" in
    NXDOMAIN|NODATA)
      EXACT_QUERY_STATE="ABSENT"
      ;;
    PRESENT)
      if grep -Fq "\"$token\"" <<<"$DNS_QUERY_OUTPUT"; then
        EXACT_QUERY_STATE="PRESENT"
      else
        EXACT_QUERY_STATE="ABSENT"
      fi
      ;;
  esac
  [[ "$EXACT_QUERY_STATE" == PRESENT ]]
}

cleanup_test_record() {
  local host="$1" port="$2" name="$3" token="$4" delete_input="$5" delete_status=0
  [[ "${TEST_RECORD_NEEDS_CLEANUP:-0}" -eq 1 ]] || return 0
  cat >"$delete_input" <<UPDATE
server $host $port
zone $RPZ_ZONE
update delete $name TXT "$token"
send
UPDATE
  if ! timeout "${RPZ_WRITE_TIMEOUT_SECONDS:-10}" nsupdate -k "$RPZ_KEY_FILE" <"$delete_input" >/dev/null 2>&1; then
    warn "临时记录精确清理更新结果不确定，继续通过权威查询确认: $name"
    delete_status=1
  fi
  exact_test_record_present "$host" "$port" "$name" "$token" || true
  case "$EXACT_QUERY_STATE" in
    ABSENT)
      if ((delete_status)); then
        fail "清理 UPDATE 返回失败；权威查询暂未发现本次 TXT，但仍需人工核对: $name"
        TEST_RECORD_NEEDS_CLEANUP=0
        return 1
      else
        pass "临时记录已精确删除并确认清理: $name"
      fi
      TEST_RECORD_NEEDS_CLEANUP=0
      return 0
      ;;
    PRESENT)
      fail "临时记录清理后仍存在: $name"
      ;;
    *)
      fail "临时记录清理状态无法确认（DNS 查询失败或非权威响应）: $name"
      ;;
  esac
  fail "请人工核对测试名称 $name 及本次随机记录标识 ${token:0:8}…；未执行宽泛删除"
  return 1
}

cleanup_on_exit() {
  local exit_code=$?
  trap - EXIT INT TERM
  if ! cleanup_test_record "${TEST_HOST:-}" "${TEST_PORT:-}" "${TEST_NAME:-}" "${TEST_TOKEN:-}" "${TEST_DELETE_INPUT:-}"; then
    exit_code=1
  fi
  if ((${#TEST_INPUT_FILES[@]})); then
    rm -f -- "${TEST_INPUT_FILES[@]}"
  fi
  exit "$exit_code"
}

handle_signal() {
  local signal="$1"
  trap - INT TERM
  fail "收到 ${signal}，已停止写入流程并进入精确清理"
  exit 130
}

write_test() {
  [[ -n "$RPZ_KEY_FILE" ]] || { fail '--write-test 需要 --key-file'; return; }
  [[ -f "$RPZ_KEY_FILE" && -r "$RPZ_KEY_FILE" && ! -L "$RPZ_KEY_FILE" ]] || { fail '--write-test 的 TSIG 文件不可读或为符号链接'; return; }
  parse_endpoint "$RPZ_PRIMARY" "$RPZ_PRIMARY_PORT" || { fail 'Primary 地址无效'; return; }
  local host="$ENDPOINT_HOST" port="$ENDPOINT_PORT" suffix name token add_input delete_input cleanup_status=0
  suffix="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
  if [[ -n "${TEST_DOMAIN:-}" ]]; then
    name="$TEST_DOMAIN"
  else
    name="${suffix}.${TEST_NAMESPACE:-_dnsguard-preflight.${RPZ_ZONE}.}"
  fi
  name="${name%.}."
  token="dnsguard-preflight-${suffix}"
  add_input="$(mktemp)"
  delete_input="$(mktemp)"
  TEST_HOST="$host"
  TEST_PORT="$port"
  TEST_NAME="$name"
  TEST_TOKEN="$token"
  TEST_DELETE_INPUT="$delete_input"
  TEST_INPUT_FILES=("$add_input" "$delete_input")
  TEST_RECORD_NEEDS_CLEANUP=0
  trap cleanup_on_exit EXIT
  trap 'handle_signal SIGINT' INT
  trap 'handle_signal SIGTERM' TERM
  if record_exists "$host" "$port" "$name"; then
    fail "临时测试名称已存在记录，拒绝覆盖或删除: $name"
    return
  elif [[ "$DNS_QUERY_STATE" != NXDOMAIN ]]; then
    fail "无法确认临时测试名称不存在（DNS 状态=$DNS_QUERY_STATE），拒绝写入: $name"
    return
  fi
  cat >"$add_input" <<UPDATE
server $host $port
zone $RPZ_ZONE
prereq nxdomain $name
update add $name 30 TXT "$token"
send
UPDATE
  TEST_RECORD_NEEDS_CLEANUP=1
  if timeout "${RPZ_WRITE_TIMEOUT_SECONDS:-10}" nsupdate -k "$RPZ_KEY_FILE" <"$add_input" >/dev/null 2>&1; then
    exact_test_record_present "$host" "$port" "$name" "$token" || true
    if [[ "$EXACT_QUERY_STATE" == PRESENT ]]; then
      pass "TSIG 写入测试成功: $name"
    elif [[ "$EXACT_QUERY_STATE" == ABSENT ]]; then
      fail "TSIG 写入返回成功，但临时记录未读回；已进入精确清理流程"
    else
      fail 'TSIG 写入返回成功，但 DNS 读回状态无法确认；已进入精确清理流程'
    fi
  else
    exact_test_record_present "$host" "$port" "$name" "$token" || true
    if [[ "$EXACT_QUERY_STATE" == PRESENT ]]; then
      fail 'nsupdate 返回失败但临时记录已存在，结果不确定；已进入精确清理流程'
    elif [[ "$EXACT_QUERY_STATE" == ABSENT ]]; then
      fail 'TSIG 写入测试失败；已执行精确清理尝试，未执行正式 RPZ 发布'
    else
      fail 'TSIG 写入结果和 DNS 状态均无法确认；已执行精确清理尝试，需人工核对'
    fi
  fi
  cleanup_test_record "$host" "$port" "$name" "$token" "$delete_input" || cleanup_status=1
  ((cleanup_status == 0)) || fail "临时记录清理未完成；需人工核对: $name"
  TEST_RECORD_NEEDS_CLEANUP=0
  trap - EXIT INT TERM
  rm -f -- "$add_input" "$delete_input"
  TEST_INPUT_FILES=()
}

while (($#)); do
  case "$1" in
    --env-file) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; ENV_FILE="$2"; shift 2 ;;
    --zone) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RPZ_ZONE="$2"; shift 2 ;;
    --primary) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RPZ_PRIMARY="$2"; shift 2 ;;
    --primary-port) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RPZ_PRIMARY_PORT="$2"; shift 2 ;;
    --secondaries) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RPZ_SECONDARIES="$2"; shift 2 ;;
    --key-file) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RPZ_KEY_FILE="$2"; shift 2 ;;
    --recursor) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RPZ_RECURSOR="$2"; shift 2 ;;
    --test-domain) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RPZ_TEST_DOMAIN="$2"; shift 2 ;;
    --test-namespace) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RPZ_TEST_NAMESPACE="$2"; shift 2 ;;
    --check-name) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RPZ_CHECK_NAME="$2"; shift 2 ;;
    --expected-a) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RPZ_EXPECTED_A="$2"; shift 2 ;;
    --render) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; OUTPUT_DIR="$2"; shift 2 ;;
    --write-test) WRITE_TEST=1; shift ;;
    --confirm) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; CONFIRM_WRITE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '未知参数: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$ENV_FILE" ]] && load_env_file
RPZ_ZONE="${RPZ_ZONE:-rpz.local}"
RPZ_PRIMARY_PORT="${RPZ_PRIMARY_PORT:-53}"
RPZ_PRIMARY="${RPZ_PRIMARY:-}"
RPZ_SECONDARIES="${RPZ_SECONDARIES:-}"

require_command dig || true
require_command awk || true
require_command stat || true
if ((WRITE_TEST)); then require_command nsupdate || true; require_command timeout || true; fi
if ((FAILURES)); then exit 2; fi

[[ -n "$RPZ_PRIMARY" ]] || fail '未配置 RPZ_PRIMARY；请使用 --primary 或环境变量'
[[ -n "$RPZ_SECONDARIES" ]] || fail '未配置 RPZ_SECONDARIES；请使用逗号分隔的 HOST[:PORT] 列表'
if ((FAILURES)); then exit 2; fi

printf 'DNSGuard RPZ 对接检查（只读模式%s）\n' "$([[ $WRITE_TEST -eq 1 ]] && echo ', 含明确写入测试' || true)"
printf 'Zone: %s\n' "$RPZ_ZONE"
check_key
parse_endpoint "$RPZ_PRIMARY" "$RPZ_PRIMARY_PORT" || fail "Primary 地址无效: $RPZ_PRIMARY"
check_endpoint Primary "$RPZ_PRIMARY" "$RPZ_PRIMARY_PORT"

IFS=',' read -r -a secondary_list <<<"$RPZ_SECONDARIES"
for endpoint in "${secondary_list[@]}"; do
  endpoint="${endpoint##+([[:space:]])}"
  endpoint="${endpoint%%+([[:space:]])}"
  [[ -n "$endpoint" ]] && check_endpoint Secondary "$endpoint"
done

if ((FAILURES)); then
  printf '结果: FAIL（只读预检查未通过，禁止写入；%d 个失败，%d 个警告）\n' "$FAILURES" "$WARNINGS" >&2
  exit 1
fi

if [[ -n "$RPZ_RECURSOR" ]]; then
  parse_endpoint "$RPZ_RECURSOR" || fail "递归 DNS 地址无效: $RPZ_RECURSOR"
  if [[ -n "$RPZ_CHECK_NAME" && -n "$RPZ_EXPECTED_A" ]]; then
    local_check="$(dig +short +time=2 +tries=1 "@$ENDPOINT_HOST" -p "$ENDPOINT_PORT" "$RPZ_CHECK_NAME" A 2>/dev/null || true)"
    if [[ "$local_check" == "$RPZ_EXPECTED_A" ]]; then
      pass "递归 RPZ 实际解析符合预期: $RPZ_CHECK_NAME -> $RPZ_EXPECTED_A"
    else
      fail "递归 RPZ 实际解析不符合预期: $RPZ_CHECK_NAME 返回=${local_check:-<empty>}，预期=$RPZ_EXPECTED_A"
    fi
  else
    warn '已配置 RPZ_RECURSOR，但未同时配置 RPZ_CHECK_NAME 和 RPZ_EXPECTED_A；实际策略验证 NOT RUN'
  fi
else
  warn '未配置 RPZ_RECURSOR；实际递归策略验证 NOT RUN'
fi

render_templates
if ((WRITE_TEST)); then
  test_domain_scope
  if ((FAILURES)); then
    printf '结果: FAIL（写入范围检查未通过，禁止写入；%d 个失败，%d 个警告）\n' "$FAILURES" "$WARNINGS" >&2
    exit 1
  fi
  if [[ "$CONFIRM_WRITE" != 'WRITE-TEST' ]]; then
    if [[ -t 0 ]]; then
      read -r -p '该操作会向 Primary 写入并删除临时 TXT 记录。输入 WRITE-TEST 继续: ' CONFIRM_WRITE
    fi
  fi
  if [[ "$CONFIRM_WRITE" == 'WRITE-TEST' ]]; then
    write_test
  else
    fail '未确认写入测试；未修改 Primary'
  fi
fi

if ((FAILURES)); then
  printf '结果: FAIL（%d 个失败，%d 个警告）\n' "$FAILURES" "$WARNINGS" >&2
  exit 1
fi
printf '结果: PASS（%d 个警告）\n' "$WARNINGS"
