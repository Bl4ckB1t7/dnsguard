#!/usr/bin/env bash
# Finalize the DNSGuard side of a staged global-deny deployment.
# This script never edits or reloads BIND. DNS checks run inside the API
# container so Docker bridge addresses are not assumed to be host-reachable.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source "$ROOT/scripts/docker-paths.sh"

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"; }

need docker
need python3
need realpath
docker compose version >/dev/null 2>&1 || die 'Docker Compose Plugin 不可用'

ENV_FILE="$(dnsguard_resolve_path "${DNSGUARD_ENV_FILE:-$ROOT/deploy/docker/dnsguard.env}" "$ROOT")"
export DNSGUARD_ENV_FILE="$ENV_FILE"
[[ -f "$ENV_FILE" ]] || die "环境文件不存在：$ENV_FILE"
[[ ! -L "$ENV_FILE" ]] || die "环境文件不能是符号链接：$ENV_FILE"

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
dnsguard_prepare_paths "$ROOT"

DATA_DIR="$DNSGUARD_DATA_DIR"
resolve_runtime_path() {
  local value="$1"
  if [[ "$value" == /var/lib/dnsguard/* ]]; then
    printf '%s/%s\n' "$DATA_DIR" "${value#/var/lib/dnsguard/}"
  elif [[ "$value" == /* ]]; then
    realpath -m -- "$value"
  else
    dnsguard_resolve_path "$value" "$ROOT"
  fi
}

STATE_FILE="$(resolve_runtime_path "${DNS_STATE_FILE:-/var/lib/dnsguard/dns-state.json}")"
JOBS_FILE="$(resolve_runtime_path "${RPZ_PUBLISH_JOBS_FILE:-/var/lib/dnsguard/publish-jobs.json}")"
BASELINE_FILE="$(resolve_runtime_path "${RPZ_GLOBAL_DENY_BASELINE_FILE:-/var/lib/dnsguard/global-deny-baseline.json}")"
GLOBAL_DENY_ZONE="${RPZ_GLOBAL_DENY_ZONE:-}"
RPZ_ZONE="${RPZ_ZONE:-}"
[[ -n "$GLOBAL_DENY_ZONE" ]] || die 'RPZ_GLOBAL_DENY_ZONE 未配置'
[[ -n "$RPZ_ZONE" ]] || die 'RPZ_ZONE 未配置'
[[ -n "${RPZ_GLOBAL_DENY_RECURSOR:-}" ]] || die 'RPZ_GLOBAL_DENY_RECURSOR 未配置'
[[ -n "${RPZ_GLOBAL_DENY_CHECK_NAME:-}" ]] || die 'RPZ_GLOBAL_DENY_CHECK_NAME 未配置'

split_endpoint() {
  python3 - "$1" <<'PY'
import sys
value = sys.argv[1].strip()
if value.startswith("[") and "]" in value:
    host, _, port = value[1:].partition("]")
    port = port.removeprefix(":") or "53"
elif value.count(":") == 1:
    host, port = value.rsplit(":", 1)
else:
    host, port = value, "53"
if not host or not port.isdigit() or not (1 <= int(port) <= 65535):
    raise SystemExit("DNS 地址无效")
print(host, port)
PY
}

COMPOSE_ARGS=(docker compose --env-file "$ENV_FILE" -f "$ROOT/compose.yaml")
if [[ -n "${DNSGUARD_BIND_NETWORK:-}" ]]; then
  [[ -f "$ROOT/compose.bind-network.yaml" ]] || die "缺少 Compose 网络 override：$ROOT/compose.bind-network.yaml"
  docker network inspect "$DNSGUARD_BIND_NETWORK" >/dev/null 2>&1 || die "BIND Docker 网络不存在：$DNSGUARD_BIND_NETWORK；脚本不会自动创建网络"
  dnsguard_validate_bind_network_cidrs "$DNSGUARD_BIND_NETWORK" "${DNS_NODE_ALLOWED_CIDRS:-}" || die 'BIND Docker 网络未获得显式 CIDR 授权'
  COMPOSE_ARGS+=(-f "$ROOT/compose.bind-network.yaml")
fi
if [[ -n "${DNSGUARD_COMPOSE_OVERRIDE:-}" ]]; then
  [[ -f "$DNSGUARD_COMPOSE_OVERRIDE" ]] || die "Compose override 不存在：$DNSGUARD_COMPOSE_OVERRIDE"
  COMPOSE_ARGS+=(-f "$DNSGUARD_COMPOSE_OVERRIDE")
fi
"${COMPOSE_ARGS[@]}" config >/dev/null || die 'Compose 配置校验失败'
pass 'Compose 配置和 BIND 网络检查通过'

API_CONTAINER="$("${COMPOSE_ARGS[@]}" ps -q dnsguard-api | head -n1)"
[[ -n "$API_CONTAINER" ]] || die '找不到运行中的 dnsguard-api；请先启动 Docker Compose'
API_STATE="$(docker inspect -f '{{.State.Status}}' "$API_CONTAINER" 2>/dev/null || true)"
[[ "$API_STATE" == running ]] || die "dnsguard-api 当前未运行：$API_STATE"
run_api_dig() { docker exec "$API_CONTAINER" dig "$@"; }

NODE_OUTPUT="$(python3 - "$STATE_FILE" "$JOBS_FILE" <<'PY'
import json
import sys
from pathlib import Path

state_path = Path(sys.argv[1])
jobs_path = Path(sys.argv[2])

def read_json(path, label):
    if not path.is_file():
        raise SystemExit(f"{label}不存在：{path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"{label}无法读取：{exc}")

state = read_json(state_path, "DNS 状态文件")
jobs = read_json(jobs_path, "RPZ 发布任务文件")
nodes = state.get("nodes")
rules = state.get("rules")
published = state.get("published")
if not isinstance(nodes, list) or not nodes:
    raise SystemExit("没有已保存的 BIND 节点配置")
if not isinstance(rules, list) or not rules:
    raise SystemExit("白名单尚未发布：当前没有规则")
if not isinstance(published, list) or not published:
    raise SystemExit("白名单尚未发布：Published 为空")

def fingerprint(rule):
    return (str(rule.get("action", "")), str(rule.get("type") or "CNAME"), str(rule.get("value", "")), str(rule.get("reason", "")))

def snapshot(ruleset):
    result = {}
    for rule in ruleset:
        domain = str(rule.get("domain", "")).strip().lower().rstrip(".")
        if not domain or domain in result:
            raise SystemExit("白名单规则存在空域名或重复域名")
        result[domain] = fingerprint(rule)
    return result

if snapshot(rules) != snapshot(published):
    raise SystemExit("白名单存在未发布变更；请先完成审核、发布和同步")
if not isinstance(jobs, list) or not jobs:
    raise SystemExit("没有可核对的 RPZ 发布任务")
latest = max(jobs, key=lambda item: (str(item.get("createdAt", "")), str(item.get("id", ""))))
status = latest.get("status", "")
sync_status = latest.get("syncStatus", "")
if status != "succeeded" or sync_status != "published":
    if status in {"queued", "running"} or sync_status == "pending_verification":
        raise SystemExit(f"最近发布任务尚未完成（status={status}, syncStatus={sync_status}）；请等待同步后重试")
    if status == "reconcile_required" or sync_status == "reconcile_required":
        raise SystemExit("最近发布任务需要人工核对，禁止继续收尾")
    raise SystemExit(f"最近发布任务未成功（status={status}, syncStatus={sync_status}）")

checks = latest.get("nodeChecks")
if not isinstance(checks, list) or len(checks) != len(nodes):
    raise SystemExit("发布任务缺少全部节点的同步验证证据；请等待同步后重试")
by_id = {}
for check in checks:
    ident = check.get("id")
    if not ident or ident in by_id or check.get("status") != "verified":
        raise SystemExit("发布任务存在未验证的 Primary/Secondary；请等待同步后重试")
    by_id[ident] = check
for node in nodes:
    check = by_id.get(node.get("id"))
    if not check or check.get("address") != node.get("address") or check.get("role") != node.get("role"):
        raise SystemExit("发布任务的节点验证证据与当前配置不一致；请等待同步后重试")

for node in nodes:
    role = str(node.get("role", "")).lower()
    if role in {"primary", "secondary"} and node.get("address"):
        print(f"{role}\t{node['address']}")
PY
)" || die "$NODE_OUTPUT"
mapfile -t NODE_ROWS <<<"$NODE_OUTPUT"
PRIMARY_ADDR=''
SECONDARY_ADDRS=()
for row in "${NODE_ROWS[@]}"; do
  IFS=$'\t' read -r role address <<<"$row"
  if [[ "$role" == primary ]]; then
    [[ -z "$PRIMARY_ADDR" ]] || die '状态文件包含多个 Primary'
    PRIMARY_ADDR="$address"
  elif [[ "$role" == secondary ]]; then
    SECONDARY_ADDRS+=("$address")
  fi
done
[[ -n "$PRIMARY_ADDR" ]] || die '没有 Primary 节点'
(( ${#SECONDARY_ADDRS[@]} > 0 )) || die '没有 Secondary 节点'
pass '白名单已发布，最近任务成功且所有节点具备 verified 同步证据'

query_soa_serial() {
  local endpoint="$1" zone="$2" host port output serial
  read -r host port < <(split_endpoint "$endpoint") || die "DNS 地址无效：$endpoint"
  output="$(run_api_dig +norecurse +short +time=2 +tries=1 "@$host" -p "$port" "$zone" SOA 2>/dev/null || true)"
  serial="$(awk 'NF >= 3 && $3 ~ /^[0-9]+$/ { print $3; exit }' <<<"$output")"
  [[ -n "$serial" ]] || die "无法读取 $zone 的权威 SOA：$endpoint"
  printf '%s\n' "$serial"
}

BUSINESS_PRIMARY_SERIAL="$(query_soa_serial "$PRIMARY_ADDR" "$RPZ_ZONE")"
for secondary in "${SECONDARY_ADDRS[@]}"; do
  secondary_serial="$(query_soa_serial "$secondary" "$RPZ_ZONE")"
  if [[ "$secondary_serial" != "$BUSINESS_PRIMARY_SERIAL" ]]; then
    die "业务 RPZ Secondary Serial=$secondary_serial，与 Primary=$BUSINESS_PRIMARY_SERIAL 不一致；请等待同步后重试"
  fi
done
pass "业务 RPZ Primary/Secondary SOA Serial 已实时一致：$BUSINESS_PRIMARY_SERIAL"

PRIMARY_SERIAL="$(query_soa_serial "$PRIMARY_ADDR" "$GLOBAL_DENY_ZONE")"
for secondary in "${SECONDARY_ADDRS[@]}"; do
  secondary_serial="$(query_soa_serial "$secondary" "$GLOBAL_DENY_ZONE")"
  if [[ "$secondary_serial" != "$PRIMARY_SERIAL" ]]; then
    die "Global Deny Secondary Serial=$secondary_serial，与 Primary=$PRIMARY_SERIAL 不一致；请等待同步后重试"
  fi
done
pass "Global Deny SOA/Serial 已一致：$PRIMARY_SERIAL"

check_trigger() {
  local endpoint="$1" host port output rcode owner
  read -r host port < <(split_endpoint "$endpoint") || die "DNS 地址无效：$endpoint"
  owner="*.$GLOBAL_DENY_ZONE."
  output="$(run_api_dig +norecurse +noall +comments +answer +time=2 +tries=1 "@$host" -p "$port" "$owner" CNAME 2>/dev/null || true)"
  rcode="$(sed -n 's/^;; ->>HEADER<<-.*status: \([^,]*\),.*/\1/p' <<<"$output" | head -n1)"
  [[ "$rcode" == NOERROR ]] || die "Global Deny 通配查询 RCODE=${rcode:-UNKNOWN}，预期 NOERROR"
  grep -E '^;; flags:' <<<"$output" | grep -Eq '(^|[ ;])aa([ ;]|$)' || die 'Global Deny 通配查询不是权威回答'
  if ! awk -v expected="$owner" '
    function norm(value) { value=tolower(value); sub(/\\.$/, "", value); return value }
    $1 != ";;" && norm($1) == norm(expected) && toupper($4) == "CNAME" && norm($5) == "." { found=1 }
    END { exit(found ? 0 : 1) }
  ' <<<"$output"; then
    die 'Global Deny Zone 缺少精确的 * CNAME . 触发项'
  fi
}
for endpoint in "$PRIMARY_ADDR" "${SECONDARY_ADDRS[@]}"; do check_trigger "$endpoint"; done
pass 'Primary/Secondary 均存在权威 * CNAME . 触发项'

BASELINE_VALUES="$(python3 - "$BASELINE_FILE" "${RPZ_GLOBAL_DENY_CHECK_NAME}" "${RPZ_GLOBAL_DENY_RECURSOR}" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
expected_name = sys.argv[2]
expected_recursor = sys.argv[3]
if not path.is_file():
    raise SystemExit(f"正常解析基线不存在：{path}")
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"正常解析基线无法读取：{exc}")
name = str(data.get("checkName", "")).strip()
recursor = str(data.get("recursor", "")).strip()
if not name or not recursor or data.get("rcode") != "NOERROR" or not data.get("observedAt"):
    raise SystemExit("正常解析基线无效；不能把任意 NXDOMAIN 当作 DENY 证据")
if name.lower().rstrip(".") != expected_name.strip().lower().rstrip(".") or recursor != expected_recursor.strip():
    raise SystemExit("正常解析基线的 checkName/recursor 与当前环境配置不一致；拒绝使用旧基线")
print(f"{name}\t{recursor}")
PY
)" || die "$BASELINE_VALUES"
IFS=$'\t' read -r CHECK_NAME RECURSOR_ADDR <<<"$BASELINE_VALUES"
read -r RECURSOR_HOST RECURSOR_PORT < <(split_endpoint "$RECURSOR_ADDR") || die "递归测试地址无效：$RECURSOR_ADDR"
RECURSIVE_OUTPUT="$(run_api_dig +comments +answer +time=2 +tries=1 "@$RECURSOR_HOST" -p "$RECURSOR_PORT" "$CHECK_NAME" A 2>/dev/null || true)"
RECURSIVE_RCODE="$(sed -n 's/^;; ->>HEADER<<-.*status: \([^,]*\),.*/\1/p' <<<"$RECURSIVE_OUTPUT" | head -n1)"
[[ "$RECURSIVE_RCODE" == NXDOMAIN ]] || die "递归拒绝验证返回 ${RECURSIVE_RCODE:-UNKNOWN}，预期 NXDOMAIN"
pass "递归拒绝效果通过：$CHECK_NAME -> NXDOMAIN（使用已保存的正常解析基线）"

ENV_BACKUP=''
ENV_CHANGED=0
if grep -Eq '^[[:space:]]*(export[[:space:]]+)?RPZ_GLOBAL_DENY_SETUP_DEFERRED[[:space:]]*=[[:space:]]*true[[:space:]]*$' "$ENV_FILE"; then
  ENV_BACKUP="$ENV_FILE.before-global-deny.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p -- "$ENV_FILE" "$ENV_BACKUP" || die '无法创建 env 保护备份，未修改原配置'
  temporary="$(mktemp "$(dirname "$ENV_FILE")/.dnsguard-env.XXXXXX")"
  cleanup() {
    if [[ -n "${temporary:-}" && -e "$temporary" ]]; then
      rm -f -- "$temporary"
    fi
  }
  trap cleanup EXIT
  python3 - "$ENV_FILE" "$temporary" <<'PY'
import re
import sys
from pathlib import Path
source = Path(sys.argv[1]).read_text(encoding="utf-8")
target = re.sub(
    r"(?m)^(\s*(?:export\s+)?)RPZ_GLOBAL_DENY_SETUP_DEFERRED\s*=.*$",
    r"\1RPZ_GLOBAL_DENY_SETUP_DEFERRED=false",
    source,
    count=1,
)
if target == source:
    raise SystemExit("未找到 RPZ_GLOBAL_DENY_SETUP_DEFERRED=true")
Path(sys.argv[2]).write_text(target, encoding="utf-8")
PY
  chmod --reference="$ENV_FILE" "$temporary"
  chown --reference="$ENV_FILE" "$temporary" 2>/dev/null || true
  mv -f -- "$temporary" "$ENV_FILE" || die "env 原子更新失败；原配置备份保留在 $ENV_BACKUP"
  temporary=''
  ENV_CHANGED=1
  pass '已安全关闭 RPZ_GLOBAL_DENY_SETUP_DEFERRED（原配置已备份）'
else
  pass 'RPZ_GLOBAL_DENY_SETUP_DEFERRED 已不是 true，重复执行无需修改配置'
fi

API_ENV="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$API_CONTAINER" 2>/dev/null || true)"
API_HEALTH="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' "$API_CONTAINER" 2>/dev/null || true)"
API_RECREATED=0
if [[ "$API_ENV" != *$'RPZ_GLOBAL_DENY_SETUP_DEFERRED=false\n'* || "$API_HEALTH" != healthy || "$ENV_CHANGED" == 1 ]]; then
  if ! "${COMPOSE_ARGS[@]}" up -d --no-build --no-deps --force-recreate dnsguard-api; then
    printf 'FAIL: API 重建失败；未构建新镜像，也未修改 BIND。\n' >&2
    printf '恢复方法：检查 Docker 日志后修正环境或网络，再重新执行本脚本。\n' >&2
    [[ -n "$ENV_BACKUP" ]] && printf '受保护 env 备份：%s\n' "$ENV_BACKUP" >&2
    exit 1
  fi
  API_RECREATED=1
fi

API_CONTAINER="$("${COMPOSE_ARGS[@]}" ps -q dnsguard-api | head -n1)"
for _ in $(seq 1 60); do
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' "$API_CONTAINER" 2>/dev/null || true)"
  [[ "$health" == healthy ]] && break
  sleep 1
done
health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' "$API_CONTAINER" 2>/dev/null || true)"
if [[ "$health" != healthy ]]; then
  printf 'FAIL: API 未恢复 healthy（当前：%s）。\n' "$health" >&2
  printf '恢复方法：docker compose --env-file "%s" %s logs --tail 100 dnsguard-api；修正问题后重新执行本脚本。\n' "$ENV_FILE" "${COMPOSE_ARGS[*]:2}" >&2
  [[ -n "$ENV_BACKUP" ]] && printf '受保护 env 备份：%s\n' "$ENV_BACKUP" >&2
  exit 1
fi
if ((API_RECREATED)); then
  pass 'dnsguard-api 已使用现有镜像重建并恢复 healthy'
else
  pass 'dnsguard-api 已确认使用 deferred=false 且当前 healthy（重复执行无需重建）'
fi
printf '%s\n' '下一步：返回 Web，执行“验证全局 DENY（只读检查）”。'
printf '%s\n' 'DNSGuard 未修改、reload 或 restart BIND。'
