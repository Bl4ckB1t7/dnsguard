#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ENV_FILE="${DNSGUARD_ENV_FILE:-$ROOT/deploy/docker/dnsguard.env}"
IMAGE="${DNSGUARD_API_IMAGE:-dnsguard-api:1.0.0}"
WEB_IMAGE="${DNSGUARD_WEB_IMAGE:-dnsguard-web:1.0.0}"
export DNSGUARD_ENV_FILE="$ENV_FILE"
export DNSGUARD_API_IMAGE="$IMAGE"
export DNSGUARD_WEB_IMAGE="$WEB_IMAGE"

die() { echo "docker-init: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

need docker
need python3
[[ -f "$ENV_FILE" ]] || {
  install -D -m 0640 deploy/docker/dnsguard.env.example "$ENV_FILE"
  die "created $ENV_FILE; replace all REPLACE_/DNS_ placeholders, then run again"
}

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

for value_name in AUTH_SECRET MONITORING_TOKEN RPZ_PRIMARY DNS_NODE_ADDRESSES; do
  value="${!value_name:-}"
  [[ -n "$value" && "$value" != REPLACE_* && "$value" != *DNS_PRIMARY* && "$value" != *DNS_SECONDARY_* ]] || die "$value_name is not configured in $ENV_FILE"
done
[[ "${APP_ENV:-}" == production ]] || die "APP_ENV must be production"
[[ "${AUTH_ENABLED:-}" == true ]] || die "AUTH_ENABLED must be true"
[[ "${#AUTH_SECRET}" -ge 32 ]] || die "AUTH_SECRET must contain at least 32 characters"
[[ "${#MONITORING_TOKEN}" -ge 32 ]] || die "MONITORING_TOKEN must contain at least 32 characters"

DATA_DIR="$ROOT/docker-data"
SECRET_DIR="$ROOT/secrets"
TLS_DIR="$ROOT/tls"
LOG_DIR="$ROOT/bind-logs"
mkdir -p "$DATA_DIR/rpz" "$SECRET_DIR" "$TLS_DIR" "$LOG_DIR"
chmod 0750 "$DATA_DIR" "$DATA_DIR/rpz" "$SECRET_DIR" "$TLS_DIR" "$LOG_DIR"

KEY_FILE="$ROOT/secrets/rpz-manager.key"
[[ -f "$KEY_FILE" ]] || die "copy the production RPZ TSIG key to $KEY_FILE; it will not be generated"
[[ -f "$TLS_DIR/fullchain.pem" && -f "$TLS_DIR/privkey.pem" ]] || die "place HTTPS certificate and key in $TLS_DIR"

if [[ ! -f "$DATA_DIR/dns-nodes.json" ]]; then
  python3 - "$DATA_DIR/dns-nodes.json" "$DNS_NODE_ADDRESSES" <<'PY'
import json
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
items = []
for raw in sys.argv[2].split(','):
    item = raw.strip()
    if not item:
        continue
    node_id, separator, address = item.partition('=')
    if not separator or not node_id.strip() or not address.strip() or ':' not in address:
        raise SystemExit(f'invalid DNS_NODE_ADDRESSES item: {item}')
    role = 'primary' if node_id.strip() == 'primary-1' else 'secondary'
    items.append({'id': node_id.strip(), 'name': node_id.strip(), 'role': role, 'address': address.strip()})
if not items or sum(node['role'] == 'primary' for node in items) != 1:
    raise SystemExit('DNS_NODE_ADDRESSES must contain exactly one primary-1')
temporary = destination.with_suffix('.json.tmp')
temporary.write_text(json.dumps(items, indent=2) + '\n', encoding='utf-8')
temporary.chmod(0o640)
temporary.replace(destination)
PY
fi

echo "Building pinned DNSGuard images (no host Go/Node.js installation required)"
docker compose --env-file "$ENV_FILE" -f compose.yaml build

if [[ ! -f "$DATA_DIR/auth.json" ]]; then
  echo "No administrator password hash exists. The next command prompts twice and writes only bcrypt output."
  docker run --rm -it --user 0:0 \
    -v "$DATA_DIR:/var/lib/dnsguard" \
    "$IMAGE" /usr/local/bin/dnsguard-authgen \
    -output /var/lib/dnsguard/auth.json -username "${AUTH_USERNAME:-admin}"
fi

# The API image uses UID/GID 10001. These operations change only local
# bind-mounted files and never alter BIND's production TSIG configuration.
docker run --rm --user 0:0 \
  -v "$DATA_DIR:/var/lib/dnsguard" \
  -v "$SECRET_DIR:/run/dnsguard-secrets" \
  "$IMAGE" sh -c '
    chown -R 10001:10001 /var/lib/dnsguard /run/dnsguard-secrets
    find /var/lib/dnsguard -type d -exec chmod 0750 {} +
    find /var/lib/dnsguard -type f -exec chmod 0640 {} +
    [ ! -e /var/lib/dnsguard/auth.json ] || chmod 0600 /var/lib/dnsguard/auth.json
    chmod 0640 /run/dnsguard-secrets/rpz-manager.key
  '

docker run --rm --user 10001:10001 \
  -v "$SECRET_DIR/rpz-manager.key:/run/key:ro" \
  "$IMAGE" sh -c 'test -r /run/key'

docker run --rm --user 101:101 \
  -v "$TLS_DIR:/run/tls:ro" \
  "$WEB_IMAGE" sh -c 'test -r /run/tls/fullchain.pem && test -r /run/tls/privkey.pem'

docker compose --env-file "$ENV_FILE" -f compose.yaml config >/dev/null
echo "Docker initialization complete. Start DNSGuard with: docker compose up -d"
