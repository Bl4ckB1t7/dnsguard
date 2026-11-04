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
  local data="$1" secrets="$2" tls="$3" config="$4"
  mkdir -p "$data/rpz" "$secrets" "$tls"
  cat >"$data/dns-state.json" <<'EOF'
{
  "nodes": [{"id":"primary-1","name":"restore-primary","role":"primary","address":"127.0.0.1:53"}],
  "rules": [{"id":"rule-1","domain":"restore.example.com","action":"redirect","type":"A","value":"192.0.2.40","reason":"restore test","status":"draft","updatedAt":"2026-01-01T00:00:00Z"}],
  "published": [{"id":"rule-0","domain":"published.example.com","action":"passthru","type":"CNAME","reason":"published history","status":"published","updatedAt":"2025-12-31T00:00:00Z"}],
  "versions": [{"id":"version-1","createdAt":"2025-12-31T00:00:00Z","mode":"artifact","rules":[]}],
  "rulesRevision": 1
}
EOF
  printf '%s\n' '{"rules":[{"domain":"old.example.com"}]}' >"$data/dns-state.json.bak"
  printf '%s\n' '[{"id":"job-1","status":"succeeded"}]' >"$data/publish-jobs.json"
  printf '%s\n' '[]' >"$data/audit.json"
  printf '%s\n' '[]' >"$data/audit.json.1"
  printf '%s\n' '{"status":"completed"}' >"$data/initialization.json"
  printf '%s\n' '{"username":"admin","passwordHash":"placeholder"}' >"$data/auth.json"
  printf '%s\n' '[{"id":"primary-1","name":"restore-primary","role":"primary","address":"127.0.0.1:53"}]' >"$data/dns-nodes.json"
  printf '%s\n' '{"enabled":false}' >"$data/telegram.json"
  printf '%s\n' 'zone artifact' >"$data/rpz/rpz.local.db"
  printf '%s\n' 'key fixture' >"$secrets/rpz-manager.key"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$tls/privkey.pem" -out "$tls/fullchain.pem" \
    -subj '/CN=localhost' >/dev/null 2>&1
  cat >"$config" <<'EOF'
APP_ENV=production
AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_SECRET=restore-test-auth-secret-012345678901234567890123456789
MONITORING_TOKEN=restore-test-monitoring-token-012345678901234567890123456789
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
  chmod 0640 "$config"
  chmod 0640 "$data"/*.json
  chmod 0600 "$data/auth.json"
  chmod 0600 "$secrets/rpz-manager.key" "$tls/privkey.pem"
  chmod 0644 "$tls/fullchain.pem"
  python3 - "$data/auth.json" <<'PY'
import json, pathlib, sys
import bcrypt
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "username": "admin",
    "passwordHash": bcrypt.hashpw(b"restore-password", bcrypt.gensalt()).decode(),
    "mustChangePassword": False,
}) + "\n")
PY
}

data="$WORK/docker-data"
secrets="$WORK/secrets"
tls="$WORK/tls"
config="$WORK/dnsguard.env"
backup_dir="$WORK/backups"
restore_data="$WORK/restored-docker-data"
restore_secrets="$WORK/restored-secrets"
restore_tls="$WORK/restored-tls"
restore_config="$WORK/restored-dnsguard.env"
make_fixture "$data" "$secrets" "$tls" "$config"

archive="$(DNSGUARD_BACKUP_MODE=docker \
  DNSGUARD_DATA_DIR="$data" \
  DNSGUARD_SECRET_DIR="$secrets" \
  DNSGUARD_TLS_DIR="$tls" \
  DNSGUARD_ENV_FILE="$config" \
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
        "config/dnsguard.env",
    }
    assert required <= names, sorted(required - names)
PY

mkdir -p "$restore_data" "$restore_secrets" "$restore_tls"
DNSGUARD_BACKUP_MODE=docker \
DNSGUARD_DATA_DIR="$restore_data" \
DNSGUARD_SECRET_DIR="$restore_secrets" \
DNSGUARD_TLS_DIR="$restore_tls" \
DNSGUARD_ENV_FILE="$restore_config" \
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
cmp "$config" "$restore_config"
[[ "$(stat -c '%a' "$restore_config")" == '600' ]]

# Start a fresh Compose stack from the restored host paths. This verifies that
# restored auth/state/audit data is consumable by the real API and Web images;
# no BIND service is included and no production endpoint is contacted.
RESTORE_ENV="$restore_config"
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

decode_captcha() {
  python3 - "$ROOT/server/captcha.go" "$1" <<'PY'
import re, sys
from pathlib import Path
source = Path(sys.argv[1]).read_text()
svg = sys.argv[2]
glyphs = {}
for char, body in re.findall(r"'([^'])': \{([^}]*)\}", source):
    rows = re.findall(r'"([01]{5})"', body)
    if len(rows) == 7:
        glyphs[char] = rows
rects = {(int(x), int(y)) for x, y in re.findall(r'<rect x="(\d+)" y="(\d+)" width="3" height="3"', svg)}
answer = []
for index in range(4):
    observed = {(row, column) for row in range(7) for column in range(5)
                if (39 + index * 18 + column * 3, 8 + row * 4) in rects}
    matches = []
    for char, rows in glyphs.items():
        expected = {(row, column) for row, pattern in enumerate(rows)
                    for column, bit in enumerate(pattern) if bit == '1'}
        if expected == observed:
            matches.append(char)
    if len(matches) != 1:
        raise SystemExit(f"ambiguous captcha glyph: {matches!r}")
    answer.append(matches[0])
print(''.join(answer))
PY
}

captcha_json="$(curl -kfsS https://127.0.0.1:19446/api/auth/captcha)"
captcha_id="$(printf '%s' "$captcha_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
captcha_svg="$(printf '%s' "$captcha_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["svg"])')"
captcha_code="$(decode_captcha "$captcha_svg")"
curl -kfsS -c "$WORK/cookies.txt" -b "$WORK/cookies.txt" \
  -H 'Content-Type: application/json' \
  --data "{\"username\":\"admin\",\"password\":\"restore-password\",\"captchaId\":\"$captcha_id\",\"captcha\":\"$captcha_code\"}" \
  https://127.0.0.1:19446/api/auth/login >/dev/null
csrf="$(awk '$6 == "dnsguard_csrf" {print $7}' "$WORK/cookies.txt")"
[[ -n "$csrf" ]]
curl -kfsS -b "$WORK/cookies.txt" https://127.0.0.1:19446/api/auth/me | grep -q '"authenticated":true'
curl -kfsS -b "$WORK/cookies.txt" https://127.0.0.1:19446/api/dns/rpz | grep -q 'restore.example.com'
curl -kfsS -b "$WORK/cookies.txt" https://127.0.0.1:19446/api/dns/nodes | grep -q 'restore-primary'
curl -kfsS -b "$WORK/cookies.txt" https://127.0.0.1:19446/api/dns/rpz/versions | grep -q 'version-1'
curl -kfsS -b "$WORK/cookies.txt" https://127.0.0.1:19446/api/dns/rpz/jobs/job-1 | grep -q 'job-1'
setup_status="$(curl -kfsS https://127.0.0.1:19446/api/setup/status)"
grep -q '"initialized":true' <<<"$setup_status"
setup_repeat_code="$(curl -ksS -o /dev/null -w '%{http_code}' -X POST https://127.0.0.1:19446/api/setup/complete -H 'Content-Type: application/json' -d '{}')"
[[ "$setup_repeat_code" == 409 || "$setup_repeat_code" == 503 ]]
docker compose -p "$RESTORE_PROJECT" -f "$ROOT/compose.yaml" --env-file "$RESTORE_ENV" exec -T dnsguard-api test -r /run/dnsguard-secrets/rpz-manager.key
[[ "$(stat -c '%a' "$restore_secrets/rpz-manager.key")" == '600' ]]
[[ "$(stat -c '%a' "$restore_tls/privkey.pem")" == '600' ]]
python3 - "$restore_data/audit.json" <<'PY'
import hashlib, json, pathlib, sys
entries = json.loads(pathlib.Path(sys.argv[1]).read_text())
previous = ""
for entry in entries:
    payload = {"timestamp": entry["timestamp"], "actor": entry["actor"], "action": entry["action"], "result": entry["result"]}
    if entry.get("ip"):
        payload["ip"] = entry["ip"]
    if entry.get("prevHash"):
        payload["prevHash"] = entry["prevHash"]
    digest = hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()
    assert entry["hash"] == digest
    assert entry.get("prevHash", "") == previous
    previous = entry["hash"]
PY
docker compose -p "$RESTORE_PROJECT" -f "$ROOT/compose.yaml" --env-file "$RESTORE_ENV" config --services | grep -qx 'dnsguard-api'
docker compose -p "$RESTORE_PROJECT" -f "$ROOT/compose.yaml" --env-file "$RESTORE_ENV" config --services | grep -qx 'dnsguard-web'
echo 'PASS: restored config, auth, RPZ rules, nodes, history, audit chain, initialization gate, TSIG and HTTPS state verified'

if DNSGUARD_BACKUP_MODE=docker \
  DNSGUARD_DATA_DIR="$WORK/unsafe-data" \
  DNSGUARD_SECRET_DIR="$WORK/unsafe-secrets" \
  DNSGUARD_TLS_DIR="$WORK/unsafe-tls" \
  RESTORE_INCLUDE_SENSITIVE=false \
  "$ROOT/scripts/restore-dnsguard.sh" "$archive" >/dev/null 2>&1; then
  echo 'restore unexpectedly accepted sensitive files without explicit opt-in' >&2
  exit 1
fi

make_tampered_archive() {
  local kind="$1" output="$2"
  python3 - "$archive" "$output" "$kind" <<'PY'
import copy, io, json, sys, tarfile
source, output, kind = sys.argv[1:]
with tarfile.open(source, 'r:gz') as bundle, tarfile.open(output, 'w:gz') as out:
    members = bundle.getmembers()
    payloads = {member.name: bundle.extractfile(member).read() for member in members}
    manifest = json.loads(payloads['manifest.json'])
    if kind == 'sensitive-marker':
        for entry in manifest['files']:
            if entry['path'] == 'config/dnsguard.env':
                entry['sensitive'] = False
    elif kind == 'path-traversal':
        manifest['files'][0]['path'] = '../escape.json'
    payloads['manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    for member in members:
        updated = copy.copy(member)
        updated.size = len(payloads[member.name])
        out.addfile(updated, io.BytesIO(payloads[member.name]))
    if kind == 'duplicate':
        member = copy.copy(members[0])
        member.size = len(payloads[member.name])
        out.addfile(member, io.BytesIO(payloads[member.name]))
PY
}

make_tampered_archive sensitive-marker "$WORK/tampered-sensitive.tar.gz"
if DNSGUARD_BACKUP_MODE=docker \
  DNSGUARD_DATA_DIR="$WORK/tampered-data" \
  DNSGUARD_SECRET_DIR="$WORK/tampered-secrets" \
  DNSGUARD_TLS_DIR="$WORK/tampered-tls" \
  DNSGUARD_ENV_FILE="$WORK/tampered.env" \
  RESTORE_INCLUDE_SENSITIVE=true \
  "$ROOT/scripts/restore-dnsguard.sh" "$WORK/tampered-sensitive.tar.gz" >/dev/null 2>&1; then
  echo 'tampered manifest sensitivity marker was accepted' >&2
  exit 1
fi
echo 'PASS: manifest sensitivity tampering cannot downgrade protected paths'

make_tampered_archive path-traversal "$WORK/tampered-path.tar.gz"
if DNSGUARD_BACKUP_MODE=docker \
  DNSGUARD_DATA_DIR="$WORK/path-data" \
  DNSGUARD_SECRET_DIR="$WORK/path-secrets" \
  DNSGUARD_TLS_DIR="$WORK/path-tls" \
  DNSGUARD_ENV_FILE="$WORK/path.env" \
  RESTORE_INCLUDE_SENSITIVE=true \
  "$ROOT/scripts/restore-dnsguard.sh" "$WORK/tampered-path.tar.gz" >/dev/null 2>&1; then
  echo 'path traversal archive was accepted' >&2
  exit 1
fi
echo 'PASS: path traversal archive rejected before writes'

make_tampered_archive duplicate "$WORK/tampered-duplicate.tar.gz"
if DNSGUARD_BACKUP_MODE=docker \
  DNSGUARD_DATA_DIR="$WORK/duplicate-data" \
  DNSGUARD_SECRET_DIR="$WORK/duplicate-secrets" \
  DNSGUARD_TLS_DIR="$WORK/duplicate-tls" \
  DNSGUARD_ENV_FILE="$WORK/duplicate.env" \
  RESTORE_INCLUDE_SENSITIVE=true \
  "$ROOT/scripts/restore-dnsguard.sh" "$WORK/tampered-duplicate.tar.gz" >/dev/null 2>&1; then
  echo 'duplicate archive member was accepted' >&2
  exit 1
fi
echo 'PASS: duplicate archive member rejected'

if DNSGUARD_BACKUP_MODE=docker \
  DNSGUARD_DATA_DIR="$WORK/limited-data" \
  DNSGUARD_SECRET_DIR="$WORK/limited-secrets" \
  DNSGUARD_TLS_DIR="$WORK/limited-tls" \
  DNSGUARD_ENV_FILE="$WORK/limited.env" \
  RESTORE_INCLUDE_SENSITIVE=true RESTORE_MAX_ARCHIVE_BYTES=1 \
  "$ROOT/scripts/restore-dnsguard.sh" "$archive" >/dev/null 2>&1; then
  echo 'oversized archive was accepted' >&2
  exit 1
fi
echo 'PASS: archive size limit rejected oversized input'

sentinel_before="$(sha256sum "$restore_data/dns-state.json" | awk '{print $1}')"
if DNSGUARD_BACKUP_MODE=docker \
  DNSGUARD_DATA_DIR="$restore_data" \
  DNSGUARD_SECRET_DIR="$restore_secrets" \
  DNSGUARD_TLS_DIR="$restore_tls" \
  DNSGUARD_ENV_FILE="$WORK/restore-no-overwrite.env" \
  RESTORE_INCLUDE_SENSITIVE=true \
  "$ROOT/scripts/restore-dnsguard.sh" "$archive" >/dev/null 2>&1; then
  echo 'restore silently overwrote existing files' >&2
  exit 1
fi
sentinel_after="$(sha256sum "$restore_data/dns-state.json" | awk '{print $1}')"
[[ "$sentinel_before" == "$sentinel_after" ]]
echo 'PASS: existing restore targets require explicit overwrite authorization and remain unchanged'

echo 'PASS: Docker backup contains complete state and sensitive files restore only with explicit opt-in'
