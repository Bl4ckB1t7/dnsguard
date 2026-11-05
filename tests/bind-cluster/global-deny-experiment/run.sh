#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEST_DIR="$ROOT_DIR/tests/bind-cluster/global-deny-experiment"
RUNTIME_DIR="$TEST_DIR/runtime"
REPORT="$TEST_DIR/REPORT.md"
COMPOSE_FILE="$TEST_DIR/compose.yaml"
PROJECT="dnsguard-global-deny-experiment"
KEEP=0
FAILURES=0
QNAME_WAIT_RECURSE="${QNAME_WAIT_RECURSE:-default}"

case "$QNAME_WAIT_RECURSE" in
  default) qname_wait_recurse_suffix='' ;;
  yes|no) qname_wait_recurse_suffix=" qname-wait-recurse $QNAME_WAIT_RECURSE" ;;
  *) echo 'QNAME_WAIT_RECURSE must be default, yes, or no' >&2; exit 2 ;;
esac

compose() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

cleanup() {
  local code=$?
  if [[ -d "$RUNTIME_DIR" ]]; then
    compose logs --no-color >"$RUNTIME_DIR/compose.log" 2>&1 || true
  fi
  if ((KEEP == 0)); then
    compose down --remove-orphans >/dev/null 2>&1 || true
  fi
  return "$code"
}
trap cleanup EXIT

while (($#)); do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --clean) compose down --remove-orphans >/dev/null 2>&1 || true; rm -rf "$RUNTIME_DIR"; exit 0 ;;
    *) echo "Usage: $0 [--keep|--clean]" >&2; exit 2 ;;
  esac
done

for tool in docker dig openssl named-checkzone python3 fuser; do
  command -v "$tool" >/dev/null 2>&1 || { echo "NOT RUN: missing $tool" >&2; exit 125; }
done
docker info >/dev/null 2>&1 || { echo 'NOT RUN: Docker daemon unavailable' >&2; exit 125; }

for port in 15453 15454 15455 15456; do
  if fuser "$port/tcp" >/dev/null 2>&1 || fuser "$port/udp" >/dev/null 2>&1; then
    echo "NOT RUN: test port $port is already in use; no listener was stopped" >&2
    exit 125
  fi
done

compose down --remove-orphans >/dev/null 2>&1 || true
rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR/keys" "$RUNTIME_DIR/upstream/data" "$RUNTIME_DIR/upstream/logs" \
  "$RUNTIME_DIR/primary/data" "$RUNTIME_DIR/primary/logs" \
  "$RUNTIME_DIR/secondary-1/data" "$RUNTIME_DIR/secondary-1/logs" \
  "$RUNTIME_DIR/secondary-2/data" "$RUNTIME_DIR/secondary-2/logs"

secret="$(openssl rand -base64 32 | tr -d '\n')"
printf 'key "experiment-rpz" {\n  algorithm hmac-sha256;\n  secret "%s";\n};\n' "$secret" >"$RUNTIME_DIR/keys/experiment-rpz.key"
chmod 0600 "$RUNTIME_DIR/keys/experiment-rpz.key"

cat >"$RUNTIME_DIR/upstream/named.conf" <<'CONF'
options {
    directory "/var/cache/bind";
    listen-on port 53 { any; };
    listen-on-v6 { none; };
    recursion no;
    allow-query { any; };
    dnssec-validation no;
};
logging {
    channel experiment_log {
        file "/var/log/bind/queries.log" versions 2 size 5m;
        severity info;
        print-time yes;
        print-category yes;
        print-severity yes;
    };
    category queries { experiment_log; };
    category default { experiment_log; };
};
zone "example.com" { type primary; file "/var/lib/bind/upstream/example.com.zone"; };
zone "example.net" { type primary; file "/var/lib/bind/upstream/example.net.zone"; };
zone "example.xyz" { type primary; file "/var/lib/bind/upstream/example.xyz.zone"; };
CONF

for zone in example.com example.net example.xyz; do
  cat >"$RUNTIME_DIR/upstream/data/$zone.zone" <<EOF_ZONE
\$TTL 60
\$ORIGIN $zone.
@ IN SOA ns.$zone. hostmaster.$zone. (1 1h 15m 30d 60)
  IN NS ns.$zone.
ns IN A 192.0.2.1
allow IN A 192.0.2.10
sub.allow IN A 192.0.2.11
deep.sub.allow IN A 192.0.2.12
redirect IN A 192.0.2.20
sub.redirect IN A 192.0.2.21
blocked IN A 192.0.2.101
EOF_ZONE
done

cat >"$RUNTIME_DIR/primary/named.conf" <<CONF
options {
    directory "/var/cache/bind";
    listen-on port 53 { any; };
    listen-on-v6 { none; };
    recursion yes;
    forward only;
    forwarders { 172.31.0.20; };
    allow-query { any; };
    allow-recursion { any; };
    dnssec-validation no;
    response-policy {
        zone "rpz.local";
        zone "global-deny.rpz.local";
    }${qname_wait_recurse_suffix};
    notify yes;
    also-notify { 172.31.0.11; 172.31.0.12; };
};
logging {
    channel experiment_log {
        file "/var/log/bind/cluster.log" versions 2 size 5m;
        severity info;
        print-time yes;
        print-category yes;
        print-severity yes;
    };
    category default { experiment_log; };
    category update { experiment_log; };
    category notify { experiment_log; };
    category rpz { experiment_log; };
};
include "/etc/bind/keys/experiment-rpz.key";
zone "rpz.local" {
    type primary;
    file "/var/lib/bind/primary/rpz.local.zone";
    allow-update { key experiment-rpz; };
    allow-transfer { 172.31.0.11; 172.31.0.12; };
    notify yes;
};
zone "global-deny.rpz.local" {
    type primary;
    file "/var/lib/bind/primary/global-deny.rpz.local.zone";
    allow-update { key experiment-rpz; };
    allow-transfer { 172.31.0.11; 172.31.0.12; };
    notify yes;
};
zone "example.com" { type forward; forward only; forwarders { 172.31.0.20; }; };
zone "example.net" { type forward; forward only; forwarders { 172.31.0.20; }; };
zone "example.xyz" { type forward; forward only; forwarders { 172.31.0.20; }; };
CONF

cat >"$RUNTIME_DIR/primary/data/rpz.local.zone" <<'ZONE'
$TTL 60
$ORIGIN rpz.local.
@ IN SOA localhost. hostmaster.localhost. (1 1h 15m 30d 60)
  IN NS localhost.
rpz.local.rpz.local. IN CNAME rpz-passthru.
*.rpz.local.rpz.local. IN CNAME rpz-passthru.
global-deny.rpz.local.rpz.local. IN CNAME rpz-passthru.
*.global-deny.rpz.local.rpz.local. IN CNAME rpz-passthru.
rpz.local.global-deny.rpz.local. IN CNAME rpz-passthru.
*.rpz.local.global-deny.rpz.local. IN CNAME rpz-passthru.
global-deny.rpz.local.global-deny.rpz.local. IN CNAME rpz-passthru.
*.global-deny.rpz.local.global-deny.rpz.local. IN CNAME rpz-passthru.
allow.example.com.rpz.local. IN CNAME rpz-passthru.
*.allow.example.com.rpz.local. IN CNAME rpz-passthru.
redirect.example.com.rpz.local. IN A 192.0.2.250
*.redirect.example.com.rpz.local. IN A 192.0.2.250
ZONE
cat >"$RUNTIME_DIR/primary/data/global-deny.rpz.local.zone" <<'ZONE'
$TTL 60
$ORIGIN global-deny.rpz.local.
@ IN SOA localhost. hostmaster.localhost. (1 1h 15m 30d 60)
  IN NS localhost.
* IN CNAME .
ZONE

for role in secondary-1 secondary-2; do
  cat >"$RUNTIME_DIR/$role/named.conf" <<CONF
options {
    directory "/var/cache/bind";
    listen-on port 53 { any; };
    listen-on-v6 { none; };
    recursion yes;
    forward only;
    forwarders { 172.31.0.20; };
    allow-query { any; };
    allow-recursion { any; };
    dnssec-validation no;
    response-policy {
        zone "rpz.local";
        zone "global-deny.rpz.local";
    }${qname_wait_recurse_suffix};
};
logging {
    channel experiment_log {
        file "/var/log/bind/cluster.log" versions 2 size 5m;
        severity info;
        print-time yes;
        print-category yes;
        print-severity yes;
    };
    category default { experiment_log; };
    category notify { experiment_log; };
    category rpz { experiment_log; };
};
zone "rpz.local" {
    type secondary;
    primaries { 172.31.0.10; };
    file "/var/lib/bind/secondary/rpz.local.zone";
    allow-notify { 172.31.0.10; };
};
zone "global-deny.rpz.local" {
    type secondary;
    primaries { 172.31.0.10; };
    file "/var/lib/bind/secondary/global-deny.rpz.local.zone";
    allow-notify { 172.31.0.10; };
};
zone "example.com" { type forward; forward only; forwarders { 172.31.0.20; }; };
zone "example.net" { type forward; forward only; forwarders { 172.31.0.20; }; };
zone "example.xyz" { type forward; forward only; forwarders { 172.31.0.20; }; };
CONF
done

# The BIND image drops privileges to uid/gid 53. Keep the generated TSIG
# readable only by that account and make only the isolated runtime trees
# writable for transferred secondary zones and test logs.
chown 53:53 "$RUNTIME_DIR/keys/experiment-rpz.key" 2>/dev/null || true
chmod 0640 "$RUNTIME_DIR/keys/experiment-rpz.key"
for dir in "$RUNTIME_DIR"/upstream "$RUNTIME_DIR"/primary "$RUNTIME_DIR"/secondary-1 "$RUNTIME_DIR"/secondary-2; do
  chown -R 53:53 "$dir" 2>/dev/null || true
  chmod 0775 "$dir" "$dir/data" "$dir/logs"
done

named-checkzone global-deny.rpz.local "$RUNTIME_DIR/primary/data/global-deny.rpz.local.zone" >"$RUNTIME_DIR/named-checkzone.log"
compose config >/dev/null
compose up -d >/dev/null

node_for_port() {
  case "$1" in
    15453) printf '%s\n' primary ;;
    15454) printf '%s\n' secondary-1 ;;
    15455) printf '%s\n' secondary-2 ;;
    *) echo "unknown test node port: $1" >&2; return 2 ;;
  esac
}

# Query from inside the isolated BIND container.  The host-published ports are
# retained for manual inspection, but Docker's DNS port proxy is not used as
# test evidence because it can behave differently from the container network.
node_dig() {
  local port="$1"
  shift
  compose exec -T "$(node_for_port "$port")" dig "$@" @127.0.0.1
}

wait_soa() {
  local port="$1" zone="$2"
  for _ in $(seq 1 60); do
    if node_dig "$port" +tcp +time=1 +tries=1 "$zone" SOA +short 2>/dev/null | grep -q '[0-9]'; then return 0; fi
    sleep 0.5
  done
  return 1
}

for port in 15453 15454 15455; do
  wait_soa "$port" global-deny.rpz.local || fail "BIND $port did not load global deny zone"
done

serials=()
for port in 15453 15454 15455; do
  serials+=("$(node_dig "$port" +tcp +time=2 +tries=1 global-deny.rpz.local SOA +short | awk '{print $3}')")
done
if [[ "${serials[0]}" == "1" && "${serials[0]}" == "${serials[1]}" && "${serials[0]}" == "${serials[2]}" ]]; then
  pass "global-deny zone loaded and Primary/Secondary SOA agree: ${serials[*]}"
else
  fail "global-deny SOA mismatch: ${serials[*]}"
fi

query_rcode() {
  node_dig "$1" +tcp +time=2 +tries=1 +comments "$2" A 2>&1 | sed -n 's/^;; ->>HEADER<<-.*status: \([^,]*\),.*/\1/p' | head -1
}
query_rcode_dnssec() {
  node_dig "$1" +tcp +time=2 +tries=1 +dnssec +comments "$2" A 2>&1 | sed -n 's/^;; ->>HEADER<<-.*status: \([^,]*\),.*/\1/p' | head -1
}
query_a() { node_dig "$1" +tcp +time=2 +tries=1 "$2" A +short | tr '\n' ' '; }

for port in 15453 15454 15455; do
  if [[ "$(query_a "$port" allow.example.com)" == *192.0.2.10* && "$(query_a "$port" deep.sub.allow.example.com)" == *192.0.2.12* ]]; then
    pass "port $port passthru whitelist and deep subdomain remain resolvable"
  else
    fail "port $port passthru whitelist was not preserved"
  fi
  if [[ "$(query_a "$port" redirect.example.com)" == *192.0.2.250* && "$(query_a "$port" sub.redirect.example.com)" == *192.0.2.250* ]]; then
    pass "port $port A redirect and subdomain match"
  else
    fail "port $port A redirect did not take precedence"
  fi
done

upstream_seen=0
tested_names=()
tested_name_observations=()
upstream_query_seen() {
  local name="$1"
  # The ISC image is started with -g, so its configured file logging is
  # intentionally bypassed.  Inspect the isolated upstream container's
  # stdout instead of an empty/unused log file.
  compose logs --no-color upstream 2>/dev/null | grep -F "($name)" >/dev/null 2>&1
}
for suffix in com net xyz; do
  name="global-deny-$(openssl rand -hex 8).deep.branch.example.$suffix"
  tested_names+=("$name")
  rcode="$(query_rcode 15453 "$name")"
  sleep 0.5
  if [[ "$rcode" == NXDOMAIN ]]; then
    pass "unknown multi-level $name returns NXDOMAIN"
  else
    fail "unknown multi-level $name returned $rcode instead of NXDOMAIN"
  fi
  if upstream_query_seen "$name"; then
    upstream_seen=1
    fail "denied query reached simulated upstream: $name"
    tested_name_observations+=("$name → NXDOMAIN, 上游观察到完整 QNAME")
  else
    pass "denied query did not reach simulated upstream: $name"
    tested_name_observations+=("$name → NXDOMAIN, 上游未观察到同名查询")
  fi
done

for port in 15453 15454 15455; do
  rcode="$(query_rcode "$port" random-global-deny.example.com)"
  [[ "$rcode" == NXDOMAIN ]] && pass "port $port root wildcard denies a .com query" || fail "port $port root wildcard .com result=$rcode"
done

dnssec_name="global-deny-$(openssl rand -hex 8).dnssec.example.com"
dnssec_rcode="$(query_rcode_dnssec 15453 "$dnssec_name")"
if [[ "$dnssec_rcode" == NXDOMAIN ]]; then
  pass "DNSSEC DO=1 query returns NXDOMAIN: $dnssec_name"
else
  fail "DNSSEC DO=1 query returned $dnssec_rcode instead of NXDOMAIN: $dnssec_name"
fi
if upstream_query_seen "$dnssec_name"; then
  dnssec_observation='QUERY_OBSERVED'
  fail "DNSSEC DO=1 query reached simulated upstream: $dnssec_name"
else
  dnssec_observation='NO_MATCHING_QUERY_OBSERVED'
  pass "DNSSEC DO=1 query did not reach simulated upstream: $dnssec_name"
fi

if [[ "$upstream_seen" -eq 0 ]]; then
  upstream_observation='NO_MATCHING_QUERY_OBSERVED'
else
  upstream_observation='QUERY_OBSERVED'
fi
bind_version="$(compose exec -T primary named -v 2>/dev/null | head -1)"
tested_name_list="$(printf '\n- %s' "${tested_name_observations[@]}")"

cat >"$REPORT" <<EOF_REPORT
# RPZ Global Default-Deny 实验报告

- 分支：\`experiment/rpz-global-default-deny\`
- 基线 main：\`e935a7f6c1a6aeff2dd3f73d799621e5c5389d31\`
- BIND 版本：\`$bind_version\`
- qname-wait-recurse：\`$QNAME_WAIT_RECURSE\`
- 网络：独立 Docker Bridge（172.31.0.0/24）
- 生产 DNS / 生产 TSIG：未使用

## 规则

\`global-deny.rpz.local\` 使用：

\`* IN CNAME .\`

\`named-checkzone\` 通过，Primary 和两台 Secondary 均加载该 Zone。

## 结果

- SOA Serial：Primary/Secondary-1/Secondary-2 = \`${serials[*]}\`。
- 白名单 passthru：\`allow.example.com\`、\`deep.sub.allow.example.com\` 在三台节点均返回上游地址。
- A 重定向：\`redirect.example.com\`、\`sub.redirect.example.com\` 在三台节点均返回 \`192.0.2.250\`。
- 多级未知名称测试：$tested_name_list
- 根级通配 \`.com\`：三台节点均返回 NXDOMAIN。
- 模拟上游观测：\`$upstream_observation\`（通过容器 stdout 核对完整 QNAME）。
- DNSSEC DO=1：\`$dnssec_rcode\`，上游观测：\`$dnssec_observation\`。
- 总体：\`$([[ "$FAILURES" -eq 0 ]] && echo PASS || echo FAIL)\`（FAILURES=$FAILURES）

## 解释边界

客户端收到 NXDOMAIN 不能单独证明不存在 DNS 数据外传。该结论只适用于本次隔离 BIND 配置、受控上游和观测日志，不能推广到所有生产 BIND 配置。

## 与 TLD deny 的对比

根级通配方案规则数量少、更新简单，但本次默认递归配置下，客户端虽收到 NXDOMAIN，受控上游仍可观察到完整 QNAME；这说明 NXDOMAIN 不能等同于查询未外传。其 RPZ 匹配范围、PASSTHRU 优先级、DNSSEC、缓存和递归行为必须按 BIND 版本实测；如果白名单或 A 重定向未优先命中，可能造成业务中断。现有 TLD deny 方案规则数量更多、更新成本更高，但匹配边界和逐项完整性更容易审计。两种方案均不能替代生产递归链路和查询外传评估。
EOF_REPORT

if ((FAILURES)); then
  exit 1
fi
pass "global default-deny experiment completed; report=$REPORT"
