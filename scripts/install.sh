#!/usr/bin/env bash
set -Eeuo pipefail

# Thin first-install wrapper. docker-init.sh remains the single Docker
# initialization implementation; this script only gathers values that cannot
# safely be inferred and prepares protected host files.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/scripts/docker-paths.sh"

die() { echo "install: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"; }
need docker
need openssl
need python3
need realpath
docker compose version >/dev/null 2>&1 || die "Docker Compose Plugin 不可用"

ENV_FILE="$(dnsguard_resolve_path "${DNSGUARD_ENV_FILE:-$ROOT/deploy/docker/dnsguard.env}" "$ROOT")"
export DNSGUARD_ENV_FILE="$ENV_FILE"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
else
  DNSGUARD_DATA_DIR="${DNSGUARD_DATA_DIR:-$ROOT/docker-data}"
  DNSGUARD_SECRET_DIR="${DNSGUARD_SECRET_DIR:-$ROOT/secrets}"
  DNSGUARD_TLS_DIR="${DNSGUARD_TLS_DIR:-$ROOT/tls}"
  DNSGUARD_BIND_LOG_DIR="${DNSGUARD_BIND_LOG_DIR:-$ROOT/bind-logs}"
  dnsguard_prepare_paths "$ROOT"

  primary="${RPZ_PRIMARY:-${DNSGUARD_PRIMARY:-}}"
  if [[ -z "$primary" ]]; then
    read -r -p "BIND Primary 地址（例如 10.0.0.10）: " primary
  fi
  [[ -n "$primary" && "$primary" != *DNS_PRIMARY* ]] || die "必须提供真实的 BIND Primary 地址"

  recursor="${RPZ_GLOBAL_DENY_RECURSOR:-${DNSGUARD_RECURSOR:-$primary:53}}"
  if [[ -z "${RPZ_GLOBAL_DENY_RECURSOR:-}" && -t 0 ]]; then
    read -r -p "递归 DNS 地址（回车使用 $recursor）: " answer
    [[ -z "$answer" ]] || recursor="$answer"
  fi
  check_name="${RPZ_GLOBAL_DENY_CHECK_NAME:-blocked.example.com}"
  umask 077
  auth_secret="$(openssl rand -hex 32)"
  monitoring_token="$(openssl rand -hex 32)"
  temporary="$(mktemp "$ROOT/.dnsguard-env.XXXXXX")"
  cleanup_temporary() {
    [[ -n "${temporary:-}" && -e "$temporary" ]] || return 0
    python3 - "$temporary" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
if path.exists():
    path.unlink()
PY
  }
  trap cleanup_temporary EXIT
  cat >"$temporary" <<ENV
DNSGUARD_DATA_DIR=$DNSGUARD_DATA_DIR
DNSGUARD_SECRET_DIR=$DNSGUARD_SECRET_DIR
DNSGUARD_TLS_DIR=$DNSGUARD_TLS_DIR
DNSGUARD_BIND_LOG_DIR=$DNSGUARD_BIND_LOG_DIR
APP_ENV=production
AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_SECRET=$auth_secret
MONITORING_TOKEN=$monitoring_token
AUTH_FILE=/var/lib/dnsguard/auth.json
DNS_NODE_CONFIG_FILE=/var/lib/dnsguard/dns-nodes.json
INITIALIZATION_FILE=/var/lib/dnsguard/initialization.json
BOOTSTRAP_TOKEN_FILE=/run/dnsguard-secrets/bootstrap.token
BOOTSTRAP_KEY_DIR=/run/dnsguard-secrets
DNS_NODE_ALLOWED_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
RPZ_ZONE=rpz.local
RPZ_PRIMARY=$primary
RPZ_PRIMARY_PORT=53
RPZ_KEY_FILE=/run/dnsguard-secrets/rpz-manager.key
RPZ_DEFAULT_DENY_MODE=global
RPZ_GLOBAL_DENY_ZONE=global-deny.rpz.local
RPZ_GLOBAL_DENY_RECURSOR=$recursor
RPZ_GLOBAL_DENY_CHECK_NAME=$check_name
RPZ_GLOBAL_DENY_SETUP_DEFERRED=true
RPZ_PUBLISH_MODE=nsupdate
RPZ_ARTIFACT_FILE=/var/lib/dnsguard/rpz/rpz.local.db
RPZ_PUBLISH_JOBS_FILE=/var/lib/dnsguard/publish-jobs.json
DNS_STATE_FILE=/var/lib/dnsguard/dns-state.json
AUDIT_FILE=/var/lib/dnsguard/audit.json
TELEGRAM_CONFIG_FILE=/var/lib/dnsguard/telegram.json
LISTEN_ADDR=0.0.0.0:8080
TRUST_PROXY_TLS=true
TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=172.28.0.0/24
ENV
  install -D -m 0640 "$temporary" "$ENV_FILE"
  cleanup_temporary
  trap - EXIT
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
dnsguard_prepare_paths "$ROOT"
mkdir -p "$DNSGUARD_DATA_DIR/rpz" "$DNSGUARD_SECRET_DIR" "$DNSGUARD_TLS_DIR" "$DNSGUARD_BIND_LOG_DIR"
chmod 0750 "$DNSGUARD_DATA_DIR" "$DNSGUARD_DATA_DIR/rpz" "$DNSGUARD_SECRET_DIR" "$DNSGUARD_TLS_DIR" "$DNSGUARD_BIND_LOG_DIR"

copy_once() {
  local source_path="$1" destination="$2" label="$3" mode="$4"
  if [[ -e "$destination" ]]; then
    [[ ! -L "$destination" ]] || die "$label 目标不能是符号链接：$destination"
    return 0
  fi
  if [[ -z "$source_path" && -t 0 ]]; then
    read -r -p "$label 源文件路径: " source_path
  fi
  [[ -n "$source_path" && -f "$source_path" && ! -L "$source_path" ]] || die "请提供有效的 $label 普通文件"
  install -D -m "$mode" "$source_path" "$destination"
}

copy_once "${RPZ_TSIG_SOURCE:-${DNSGUARD_TSIG_SOURCE:-}}" "$DNSGUARD_SECRET_DIR/rpz-manager.key" "RPZ TSIG Key" 0640
copy_once "${TLS_CERT_SOURCE:-${DNSGUARD_TLS_CERT_SOURCE:-}}" "$DNSGUARD_TLS_DIR/fullchain.pem" "HTTPS 证书" 0644
copy_once "${TLS_KEY_SOURCE:-${DNSGUARD_TLS_KEY_SOURCE:-}}" "$DNSGUARD_TLS_DIR/privkey.pem" "HTTPS 私钥" 0640

bootstrap="$DNSGUARD_SECRET_DIR/bootstrap.token"
if [[ ! -e "$bootstrap" ]]; then
  temporary="$(mktemp "$DNSGUARD_SECRET_DIR/.bootstrap.XXXXXX")"
  chmod 0600 "$temporary"
  openssl rand -hex 32 >"$temporary"
  install -m 0600 "$temporary" "$bootstrap"
  python3 - "$temporary" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
if path.exists():
    path.unlink()
PY
fi
[[ ! -L "$bootstrap" && "$(wc -c <"$bootstrap")" -ge 32 ]] || die "Bootstrap Token 文件无效"

echo "准备 Docker Compose（不会覆盖现有数据、Token 或证书）"
"$ROOT/scripts/docker-init.sh"
docker compose --env-file "$ENV_FILE" -f compose.yaml up -d
docker compose --env-file "$ENV_FILE" -f compose.yaml ps
host="${DNSGUARD_INSTALL_HOST:-localhost}"
port="${DNSGUARD_WEB_PORT:-443}"
echo "安装完成：https://${host}:${port}/"
echo "Bootstrap Token 未显示；请在受保护终端读取：cat '$bootstrap'"
echo "下一步：打开 Web 完成 BIND 对接；在 RPZ 规则页面导入 TXT/JSON 白名单（只生成 draft），人工发布并确认同步后再启用全局 DENY。"
