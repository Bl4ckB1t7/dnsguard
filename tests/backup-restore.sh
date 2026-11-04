#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dnsguard-backup-test.XXXXXX")"
RESTORE_PROJECT="dnsguard-backup-restore-$RANDOM"
RESTORE_ENV=""

cleanup() {
  if [[ -n "$RESTORE_ENV" ]]; then
    docker compose -p "$RESTORE_PROJECT" -f "$ROOT/compose.yaml" --env-file "$RESTORE_ENV" down --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

make_fixture() {
  local data="$1" secrets="$2" tls="$3"
  mkdir -p "$data/rpz" "$secrets" "$tls"
  printf '%s\n' '{"rules":[{"domain":"restore.example.com"}]}' >"$data/dns-state.json"
  printf '%s\n' '{"rules":[{"domain":"old.example.com"}]}' >"$data/dns-state.json.bak"
  printf '%s\n' '[{"id":"job-1","status":"succeeded"}]' >"$data/publish-jobs.json"
  printf '%s\n' '[]' >"$data/audit.json"
  printf '%s\n' '[]' >"$data/audit.json.1"
  printf '%s\n' '{"status":"completed"}' >"$data/initialization.json"
  printf '%s\n' '{"username":"admin","passwordHash":"$2b$12$0PGbIizhyrBXRqrz2a9phexSlrozHutf7KxHAaP.Tnpr9iTd8Emvy"}' >"$data/auth.json"
  printf '%s\n' '[{"id":"primary-1","name":"restore-primary","role":"primary","address":"127.0.0.1:53"}]' >"$data/dns-nodes.json"
  printf '%s\n' '{"enabled":false}' >"$data/telegram.json"
  printf '%s\n' 'zone artifact' >"$data/rpz/rpz.local.db"
  printf '%s\n' 'key fixture' >"$secrets/rpz-manager.key"
  printf '%s\n' 'certificate fixture' >"$tls/fullchain.pem"
  printf '%s\n' 'private key fixture' >"$tls/privkey.pem"
  chmod 0640 "$data"/*.json
  chmod 0600 "$data/auth.json"
  chmod 0600 "$secrets/rpz-manager.key" "$tls/privkey.pem"
  chmod 0644 "$tls/fullchain.pem"
}

data="$WORK/docker-data"
secrets="$WORK/secrets"
tls="$WORK/tls"
backup_dir="$WORK/backups"
restore_data="$WORK/restored-docker-data"
restore_secrets="$WORK/restored-secrets"
restore_tls="$WORK/restored-tls"
make_fixture "$data" "$secrets" "$tls"

archive="$(DNSGUARD_BACKUP_MODE=docker \
  DNSGUARD_DATA_DIR="$data" \
  DNSGUARD_SECRET_DIR="$secrets" \
  DNSGUARD_TLS_DIR="$tls" \
  BACKUP_INCLUDE_SENSITIVE=true \
  BACKUP_DIR="$backup_dir" \
  "$ROOT/scripts/backup-dnsguard.sh")"

[[ -f "$archive" ]]
[[ "$(stat -c '%a' "$archive")" == 600 ]]
python3 - "$archive" <<'PY'
import json, sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as bundle:
    manifest = json.loads(bundle.extractfile("manifest.json").read())
    assert manifest["format"] == 2 and manifest["mode"] == "docker"
    names = {item["path"] for item in manifest["files"]}
    required = {
        "docker-data/dns-state.json",
        "docker-data/dns-state.json.bak",
        "docker-data/publish-jobs.json",
        "docker-data/audit.json.1",
        "docker-data/initialization.json",
        "docker-data/auth.json",
        "docker-data/telegram.json",
        "docker-data/rpz/rpz.local.db",
        "secrets/rpz-manager.key",
        "tls/privkey.pem",
    }
    assert required <= names, sorted(required - names)
PY

mkdir -p "$restore_data" "$restore_secrets" "$restore_tls"
DNSGUARD_BACKUP_MODE=docker \
DNSGUARD_DATA_DIR="$restore_data" \
DNSGUARD_SECRET_DIR="$restore_secrets" \
DNSGUARD_TLS_DIR="$restore_tls" \
RESTORE_INCLUDE_SENSITIVE=true \
"$ROOT/scripts/restore-dnsguard.sh" "$archive" >/dev/null
cmp "$data/dns-state.json" "$restore_data/dns-state.json"
cmp "$data/dns-state.json.bak" "$restore_data/dns-state.json.bak"
cmp "$data/publish-jobs.json" "$restore_data/publish-jobs.json"
cmp "$data/audit.json.1" "$restore_data/audit.json.1"
cmp "$data/auth.json" "$restore_data/auth.json"
cmp "$data/dns-nodes.json" "$restore_data/dns-nodes.json"
cmp "$secrets/rpz-manager.key" "$restore_secrets/rpz-manager.key"
cmp "$tls/privkey.pem" "$restore_tls/privkey.pem"

# Start a fresh Compose stack from the restored host paths. This verifies that
# restored auth/state/audit data is consumable by the real API and Web images;
# no BIND service is included and no production endpoint is contacted.
RESTORE_ENV="$WORK/restore.env"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$restore_tls/privkey.pem" -out "$restore_tls/fullchain.pem" \
  -subj '/CN=localhost' >/dev/null 2>&1
chmod 0644 "$restore_tls/fullchain.pem"; chmod 0640 "$restore_tls/privkey.pem"
chown 101:101 "$restore_tls/privkey.pem" 2>/dev/null || true
cat >"$RESTORE_ENV" <<EOF
APP_ENV=production
AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_SECRET=$(openssl rand -hex 32)
MONITORING_TOKEN=$(openssl rand -hex 32)
AUTH_FILE=/var/lib/dnsguard/auth.json
DNS_NODE_CONFIG_FILE=/var/lib/dnsguard/dns-nodes.json
INITIALIZATION_FILE=/var/lib/dnsguard/initialization.json
DNS_NODE_ALLOWED_CIDRS=127.0.0.0/8
RPZ_ZONE=rpz.local
RPZ_PUBLISH_MODE=artifact
RPZ_KEY_FILE=/run/dnsguard-secrets/rpz-manager.key
RPZ_ARTIFACT_FILE=/var/lib/dnsguard/rpz/rpz.local.db
RPZ_PUBLISH_JOBS_FILE=/var/lib/dnsguard/publish-jobs.json
DNS_STATE_FILE=/var/lib/dnsguard/dns-state.json
AUDIT_FILE=/var/lib/dnsguard/audit.json
TELEGRAM_CONFIG_FILE=/var/lib/dnsguard/telegram.json
TRUST_PROXY_TLS=true
TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=172.30.2.0/24
LISTEN_ADDR=0.0.0.0:8080
EOF
chmod 0640 "$RESTORE_ENV"
export DNSGUARD_ENV_FILE="$RESTORE_ENV"
export DNSGUARD_DATA_DIR="$restore_data" DNSGUARD_SECRET_DIR="$restore_secrets" DNSGUARD_TLS_DIR="$restore_tls"
export DNSGUARD_INTERNAL_NETWORK_NAME="$RESTORE_PROJECT-internal" DNSGUARD_INTERNAL_SUBNET=172.30.2.0/24
export DNSGUARD_WEB_BIND_IP=127.0.0.1 DNSGUARD_WEB_PORT=19446
export DNSGUARD_API_IMAGE=dnsguard-api:1.0.0 DNSGUARD_WEB_IMAGE=dnsguard-web:1.0.0
if ! docker compose -p "$RESTORE_PROJECT" -f "$ROOT/compose.yaml" --env-file "$RESTORE_ENV" up -d >/dev/null; then
  docker compose -p "$RESTORE_PROJECT" -f "$ROOT/compose.yaml" --env-file "$RESTORE_ENV" logs --no-color
  exit 1
fi
for _ in $(seq 1 45); do
  curl -kfsS "https://127.0.0.1:19446/api/health" >/dev/null 2>&1 && break
  sleep 1
done
if ! curl -kfsS "https://127.0.0.1:19446/api/health" >/dev/null; then
  docker compose -p "$RESTORE_PROJECT" -f "$ROOT/compose.yaml" --env-file "$RESTORE_ENV" logs --no-color
  exit 1
fi
[[ "$(curl -ksS -o /dev/null -w '%{http_code}' "https://127.0.0.1:19446/api/dns/rpz")" == 401 ]]
docker compose -p "$RESTORE_PROJECT" -f "$ROOT/compose.yaml" --env-file "$RESTORE_ENV" exec -T dnsguard-api test -r /var/lib/dnsguard/auth.json
echo 'PASS: restored JSON starts a fresh Compose stack and protected API requires authentication'

if DNSGUARD_BACKUP_MODE=docker \
  DNSGUARD_DATA_DIR="$WORK/unsafe-data" \
  DNSGUARD_SECRET_DIR="$WORK/unsafe-secrets" \
  DNSGUARD_TLS_DIR="$WORK/unsafe-tls" \
  RESTORE_INCLUDE_SENSITIVE=false \
  "$ROOT/scripts/restore-dnsguard.sh" "$archive" >/dev/null 2>&1; then
  echo 'restore unexpectedly accepted sensitive files without explicit opt-in' >&2
  exit 1
fi

echo 'PASS: Docker backup contains complete state and sensitive files restore only with explicit opt-in'
