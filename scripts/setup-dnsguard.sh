#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${DNSGUARD_INSTALL_DIR:-/opt/dnsguard}"
CONFIG_DIR="${DNSGUARD_CONFIG_DIR:-/etc/dnsguard}"
DATA_DIR="${DNSGUARD_DATA_DIR:-/var/lib/dnsguard}"
SYSTEM_USER="${DNSGUARD_USER:-dnsguard}"
SYSTEM_GROUP="${DNSGUARD_GROUP:-dnsguard}"
CONFIG_FILE="$CONFIG_DIR/dnsguard.env"
AUTH_FILE="${AUTH_FILE:-$CONFIG_DIR/auth.json}"
NODE_FILE="$CONFIG_DIR/dns-nodes.json"
NONINTERACTIVE="${DNSGUARD_NONINTERACTIVE:-false}"

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0" >&2; exit 1; }
[[ -d "$INSTALL_DIR" ]] || { echo "Install directory not found: $INSTALL_DIR" >&2; exit 1; }
for command_name in openssl python3 install; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "Missing required command: $command_name" >&2; exit 2; }
done

mkdir -p "$CONFIG_DIR" "$DATA_DIR/rpz"
chown root:"$SYSTEM_GROUP" "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR"
chmod 0750 "$DATA_DIR" "$DATA_DIR/rpz"

ask_required() {
  local variable=$1 prompt=$2 default=${3:-} value
  value="${!variable:-}"
  if [[ -z "$value" && "$NONINTERACTIVE" != true ]]; then
    read -r -p "$prompt${default:+ [$default]}: " value
  fi
  value="${value:-$default}"
  [[ -n "$value" ]] || { echo "$variable is required" >&2; exit 2; }
  printf -v "$variable" '%s' "$value"
}

ask_optional() {
  local variable=$1 prompt=$2 default=${3:-} value
  value="${!variable:-}"
  if [[ -z "$value" && "$NONINTERACTIVE" != true ]]; then
    read -r -p "$prompt${default:+ [$default]}: " value
  fi
  printf -v "$variable" '%s' "${value:-$default}"
}

ask_required DNSGUARD_PRIMARY_ADDRESS "Primary DNS address (host:port)"
ask_required DNSGUARD_SECONDARY_ADDRESSES "Secondary DNS addresses (comma-separated)"
ask_required DNSGUARD_RPZ_KEY_FILE "TSIG key file" "$CONFIG_DIR/keys/rpz-manager.key"
ask_required DNSGUARD_RPZ_LOG_FILES "BIND RPZ log files (comma-separated)" "/var/log/named/rpz.log"
ask_optional DNSGUARD_BIND_INTERFACE "Management interface (leave blank when Web bind address is set)"
ask_optional DNSGUARD_WEB_BIND_ADDRESS "Web bind address (empty = interface IPv4)"
ask_required DNSGUARD_AUTH_USERNAME "Login username" "admin"

if [[ -z "$DNSGUARD_BIND_INTERFACE" && -z "$DNSGUARD_WEB_BIND_ADDRESS" ]]; then
  echo "Set a management interface or an explicit Web bind address" >&2
  exit 2
fi

if [[ "$DNSGUARD_PRIMARY_ADDRESS" != *:* ]]; then
  echo "Primary DNS address must use host:port form" >&2
  exit 2
fi
RPZ_PRIMARY="${DNSGUARD_PRIMARY_ADDRESS%:*}"
RPZ_PRIMARY_PORT="${DNSGUARD_PRIMARY_ADDRESS##*:}"
[[ "$RPZ_PRIMARY_PORT" =~ ^[0-9]+$ ]] || { echo "Invalid primary DNS port" >&2; exit 2; }
RPZ_KEY_FILE="$CONFIG_DIR/keys/rpz-manager.key"

existing_auth_secret=""
existing_monitoring_token=""
if [[ -r "$CONFIG_FILE" ]]; then
  existing_auth_secret="$(awk -F= '$1 == "AUTH_SECRET" {print substr($0, index($0, "=") + 1); exit}' "$CONFIG_FILE" || true)"
  existing_monitoring_token="$(awk -F= '$1 == "MONITORING_TOKEN" {print substr($0, index($0, "=") + 1); exit}' "$CONFIG_FILE" || true)"
fi
AUTH_SECRET="${AUTH_SECRET:-${existing_auth_secret:-$(openssl rand -hex 32)}}"
MONITORING_TOKEN="${MONITORING_TOKEN:-${existing_monitoring_token:-$(openssl rand -hex 32)}}"

tmp_config=$(mktemp)
trap 'rm -f "$tmp_config"' EXIT
cat > "$tmp_config" <<EOF_CONFIG
APP_ENV=production
BUILD_ON_START=false
WEB_MODE=preview
BIND_INTERFACE=$DNSGUARD_BIND_INTERFACE
WEB_BIND_ADDRESS=$DNSGUARD_WEB_BIND_ADDRESS
AUTH_USERNAME=$DNSGUARD_AUTH_USERNAME
AUTH_SECRET=$AUTH_SECRET
AUTH_ENABLED=true
AUTH_FILE=$AUTH_FILE
DNS_NODE_CONFIG_FILE=$NODE_FILE
DNS_NODE_ALLOWED_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
DNS_NODE_ALLOWED_HOSTS=
RPZ_LOG_FILES=$DNSGUARD_RPZ_LOG_FILES
RPZ_LOG_MAX_BYTES=5242880
RPZ_HIT_DEDUP_SECONDS=2
RPZ_PUBLISH_TIMEOUT_SECONDS=15
RPZ_PUBLISH_RETRIES=2
RPZ_PUBLISH_RETRY_BACKOFF_SECONDS=1
DNS_HEALTH_CACHE_SECONDS=5
DNS_HEALTH_INTERVAL_SECONDS=10
TRUST_PROXY_TLS=true
TRUST_PROXY_HEADERS=false
TRUSTED_PROXY_CIDRS=127.0.0.0/8,::1/128
TLS_CERT_FILE=
TLS_KEY_FILE=
MONITORING_TOKEN=$MONITORING_TOKEN
TELEGRAM_CONFIG_FILE=$DATA_DIR/telegram.json
LISTEN_ADDR=127.0.0.1:8080
DNS_STATE_FILE=$DATA_DIR/dns-state.json
AUDIT_FILE=$DATA_DIR/audit.json
AUDIT_MAX_ENTRIES=2000
AUDIT_ROTATE_BYTES=5242880
AUDIT_ROTATE_BACKUPS=3
RPZ_ZONE=rpz.local
RPZ_PUBLISH_MODE=nsupdate
RPZ_ARTIFACT_FILE=$DATA_DIR/rpz/rpz.local.db
BACKUP_RETENTION_COUNT=14
RPZ_PRIMARY=$RPZ_PRIMARY
RPZ_PRIMARY_PORT=$RPZ_PRIMARY_PORT
RPZ_KEY_FILE=$RPZ_KEY_FILE
EOF_CONFIG
install -o root -g "$SYSTEM_GROUP" -m 0640 "$tmp_config" "$CONFIG_FILE"

python3 - "$NODE_FILE" "$DNSGUARD_PRIMARY_ADDRESS" "$DNSGUARD_SECONDARY_ADDRESSES" <<'PY'
import json
import pathlib
import sys

path, primary, secondaries = sys.argv[1:]
nodes = [{"id": "primary-1", "name": "DNS Primary", "role": "primary", "address": primary}]
for index, address in enumerate((item.strip() for item in secondaries.split(",")), 1):
    if address:
        nodes.append({"id": f"secondary-{index}", "name": f"DNS Secondary {index}", "role": "secondary", "address": address})
if len(nodes) < 2:
    raise SystemExit("at least one secondary DNS address is required")
temporary = pathlib.Path(path + ".tmp")
temporary.write_text(json.dumps(nodes, indent=2) + "\n", encoding="utf-8")
temporary.chmod(0o640)
temporary.replace(pathlib.Path(path))
PY
chown root:"$SYSTEM_GROUP" "$NODE_FILE"
chmod 0640 "$NODE_FILE"

[[ -r "$DNSGUARD_RPZ_KEY_FILE" ]] || { echo "TSIG key file is not readable: $DNSGUARD_RPZ_KEY_FILE" >&2; exit 1; }
install -d -o root -g "$SYSTEM_GROUP" -m 0750 "$CONFIG_DIR/keys"
if [[ "$DNSGUARD_RPZ_KEY_FILE" != "$RPZ_KEY_FILE" ]]; then
  install -o root -g "$SYSTEM_GROUP" -m 0640 "$DNSGUARD_RPZ_KEY_FILE" "$RPZ_KEY_FILE"
else
  chown root:"$SYSTEM_GROUP" "$RPZ_KEY_FILE"
  chmod 0640 "$RPZ_KEY_FILE"
fi

if [[ ! -r "$AUTH_FILE" ]]; then
  echo "Creating the initial bcrypt login file. The password is not stored in dnsguard.env."
  (cd "$INSTALL_DIR/server" && go run ./cmd/authgen -output "$AUTH_FILE" -username "$DNSGUARD_AUTH_USERNAME")
fi
chown "$SYSTEM_USER:$SYSTEM_GROUP" "$AUTH_FILE"
chmod 0600 "$AUTH_FILE"

DNSGUARD_CONFIG_FILE="$CONFIG_FILE" "$INSTALL_DIR/scripts/preflight-dnsguard.sh"
echo "DNSGuard configuration is ready. Start with: systemctl start dnsguard-api.service"
