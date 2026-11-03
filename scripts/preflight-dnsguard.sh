#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${DNSGUARD_CONFIG_FILE:-/etc/dnsguard/dnsguard.env}"
if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "Configuration file is not readable: $CONFIG_FILE" >&2
  exit 2
fi
# shellcheck disable=SC1090
source "$CONFIG_FILE"

fail() {
  echo "PREFLIGHT FAILED: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

require_command curl
require_command dig
require_command python3

if [[ "${RPZ_PUBLISH_MODE:-artifact}" == "nsupdate" ]]; then
  require_command nsupdate
  require_command named-checkzone
fi

[[ "${APP_ENV:-}" == "production" ]] || fail "APP_ENV must be production"
[[ "${AUTH_ENABLED:-}" == "true" ]] || fail "AUTH_ENABLED must be true"
AUTH_SECRET="${AUTH_SECRET:-}"
MONITORING_TOKEN="${MONITORING_TOKEN:-}"
AUTH_SECRET_LENGTH=${#AUTH_SECRET}
[[ "$AUTH_SECRET_LENGTH" -ge 32 ]] || fail "AUTH_SECRET must be at least 32 characters"
MONITORING_TOKEN_LENGTH=${#MONITORING_TOKEN}
[[ "$MONITORING_TOKEN_LENGTH" -ge 32 ]] || fail "MONITORING_TOKEN must be at least 32 characters"

[[ -r "${AUTH_FILE:-}" ]] || fail "AUTH_FILE is not readable: ${AUTH_FILE:-unset}"
python3 - "$AUTH_FILE" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
try:
    payload = json.loads(path.read_text())
except Exception as exc:
    raise SystemExit(f"invalid AUTH_FILE: {exc}")
password_hash = payload.get("passwordHash", "")
if not isinstance(password_hash, str) or not password_hash.startswith("$2"):
    raise SystemExit("AUTH_FILE must contain a bcrypt passwordHash")
PY

[[ -r "${DNS_NODE_CONFIG_FILE:-}" ]] || fail "DNS_NODE_CONFIG_FILE is not readable: ${DNS_NODE_CONFIG_FILE:-unset}"
NODE_ADDRESSES_TEXT="$(python3 - "$DNS_NODE_CONFIG_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    nodes = json.load(handle)
if not isinstance(nodes, list) or not nodes:
    raise SystemExit("DNS_NODE_CONFIG_FILE must contain a non-empty array")
for node in nodes:
    address = node.get("address") if isinstance(node, dict) else None
    if not isinstance(address, str) or ":" not in address:
        raise SystemExit("each DNS node must have an address in host:port form")
    print(address)
PY
)" || fail "invalid DNS_NODE_CONFIG_FILE"
mapfile -t NODE_ADDRESSES <<<"$NODE_ADDRESSES_TEXT"
[[ "${#NODE_ADDRESSES[@]}" -gt 0 ]] || fail "no DNS nodes configured"

for address in "${NODE_ADDRESSES[@]}"; do
  host="${address%:*}"
  port="${address##*:}"
  [[ "$host" != "$address" && "$port" =~ ^[0-9]+$ ]] || fail "invalid DNS node address: $address"
  dig +short +time=2 +tries=1 "@$host" -p "$port" SOA . >/dev/null \
    || fail "DNS node is unreachable: $address"
done

if [[ "${RPZ_PUBLISH_MODE:-artifact}" == "nsupdate" ]]; then
  [[ -r "${RPZ_KEY_FILE:-}" ]] || fail "RPZ_KEY_FILE is not readable: ${RPZ_KEY_FILE:-unset}"
  [[ -n "${RPZ_PRIMARY:-}" ]] || fail "RPZ_PRIMARY is required in nsupdate mode"
  RPZ_PRIMARY_PORT="${RPZ_PRIMARY_PORT:-53}"
  dig +short +time=2 +tries=1 "@${RPZ_PRIMARY}" -p "$RPZ_PRIMARY_PORT" SOA "${RPZ_ZONE:-rpz.local}" >/dev/null \
    || fail "RPZ primary is unreachable: ${RPZ_PRIMARY}:${RPZ_PRIMARY_PORT}"
fi

if [[ "${TRUST_PROXY_TLS:-false}" != "true" ]]; then
  [[ -r "${TLS_CERT_FILE:-}" ]] || fail "TLS_CERT_FILE is not readable"
  [[ -r "${TLS_KEY_FILE:-}" ]] || fail "TLS_KEY_FILE is not readable"
fi

echo "PREFLIGHT OK: $((${#NODE_ADDRESSES[@]})) DNS node(s) reachable; production security checks passed."
