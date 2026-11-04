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
RPZ_CHECK_NAME="${RPZ_CHECK_NAME-}"
RPZ_EXPECTED_A="${RPZ_EXPECTED_A-}"
ENV_FILE="${RPZ_CONNECT_ENV_FILE-}"
OUTPUT_DIR=""
WRITE_TEST=0
CONFIRM_WRITE="${RPZ_CONNECT_CONFIRM-}"
FAILURES=0
WARNINGS=0
PRIMARY_SERIAL=""

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
        RPZ_ZONE|RPZ_PRIMARY|RPZ_PRIMARY_PORT|RPZ_SECONDARIES|RPZ_KEY_FILE|RPZ_RECURSOR|RPZ_TEST_DOMAIN|RPZ_CHECK_NAME|RPZ_EXPECTED_A)
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

write_test() {
  [[ -n "$RPZ_KEY_FILE" ]] || { fail '--write-test 需要 --key-file'; return; }
  [[ -f "$RPZ_KEY_FILE" && -r "$RPZ_KEY_FILE" ]] || { fail '--write-test 的 TSIG 文件不可读'; return; }
  parse_endpoint "$RPZ_PRIMARY" "$RPZ_PRIMARY_PORT" || { fail 'Primary 地址无效'; return; }
  local host="$ENDPOINT_HOST" port="$ENDPOINT_PORT"
  local suffix name add_input delete_input answer
  suffix="$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
  name="${RPZ_TEST_DOMAIN:-_dnsguard_preflight_${suffix}.${RPZ_ZONE}}"
  name="${name%.}."
  add_input="$(mktemp)"
  delete_input="$(mktemp)"
  cat >"$add_input" <<UPDATE
server $host $port
zone $RPZ_ZONE
update add $name 30 TXT "dnsguard-preflight"
send
UPDATE
  cat >"$delete_input" <<UPDATE
server $host $port
zone $RPZ_ZONE
update delete $name TXT
send
UPDATE
  local added=0 cleaned=0
  if nsupdate -k "$RPZ_KEY_FILE" <"$add_input" >/dev/null 2>&1; then
    added=1
    answer="$(dig +short +time=2 +tries=1 "@$host" -p "$port" "$name" TXT 2>/dev/null || true)"
    if [[ "$answer" == *dnsguard-preflight* ]]; then
      pass "TSIG 写入测试成功: $name"
    else
      fail 'TSIG 写入返回成功，但临时记录未读回'
    fi
  else
    fail 'TSIG 写入测试失败；未执行正常发布'
  fi
  if ((added)); then
    if nsupdate -k "$RPZ_KEY_FILE" <"$delete_input" >/dev/null 2>&1; then
      cleaned=1
      if [[ -z "$(dig +short +time=2 +tries=1 "@$host" -p "$port" "$name" TXT 2>/dev/null || true)" ]]; then
        pass "临时记录已删除并确认清理: $name"
      else
        fail "清理命令返回成功，但临时记录仍存在: $name"
      fi
    else
      fail "临时记录清理失败: $name；请按文档人工删除"
    fi
  fi
  rm -f "$add_input" "$delete_input"
  ((cleaned)) || true
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
if ((WRITE_TEST)); then require_command nsupdate || true; fi
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
