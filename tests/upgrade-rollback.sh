#!/usr/bin/env bash
set -Eeuo pipefail

# Isolated v1.1.1 -> current-main upgrade and snapshot rollback rehearsal.
# This script creates only resources labelled with the run id and binds all
# state to a temporary directory. It never touches a user's Compose project.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${UPGRADE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
RUNTIME_DIR="${UPGRADE_RUNTIME_DIR:-$ROOT_DIR/tests/upgrade-runtime/$RUN_ID}"
BASELINE_REF="${UPGRADE_BASELINE_REF:-v1.1.1}"
CURRENT_REF="${UPGRADE_CURRENT_REF:-HEAD}"
OLD_IMAGE="dnsguard-upgrade-${RUN_ID}-v111"
NEW_IMAGE="dnsguard-upgrade-${RUN_ID}-candidate"
NETWORK="dnsguard-upgrade-${RUN_ID}-net"
OLD_CONTAINER="dnsguard-upgrade-${RUN_ID}-old"
NEW_CONTAINER="dnsguard-upgrade-${RUN_ID}-new"
PORT="${UPGRADE_HOST_PORT:-18881}"
BASE_URL="http://127.0.0.1:${PORT}"
REPORT="$RUNTIME_DIR/upgrade-rollback-report.md"

declare -a NAMES=() STATUS=() EVIDENCE=()

record() {
  NAMES+=("$1"); STATUS+=("$2"); EVIDENCE+=("$3")
  printf '%-10s %s\n' "$2" "$1"
}

run_case() {
  local name="$1" fn="$2" evidence="$RUNTIME_DIR/evidence/${#NAMES[@]}-$1.log" code
  mkdir -p "$RUNTIME_DIR/evidence"
  set +e
  (set -e; "$fn") >"$evidence" 2>&1
  code=$?
  set -e
  if ((code == 0)); then
    record "$name" PASS "$evidence"
  elif ((code == 125)); then
    record "$name" 'NOT RUN' "$evidence"
  else
    record "$name" FAIL "$evidence"
  fi
}

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 2; }; }

cleanup() {
  local code=$?
  docker logs "$OLD_CONTAINER" >"$RUNTIME_DIR/old-container.log" 2>&1 || true
  docker logs "$NEW_CONTAINER" >"$RUNTIME_DIR/new-container.log" 2>&1 || true
  docker rm -f "$OLD_CONTAINER" "$NEW_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  if ((code == 0)); then
    rm -rf "$RUNTIME_DIR/images" "$RUNTIME_DIR/src-v111"
  fi
  write_report || true
  return "$code"
}

write_report() {
  mkdir -p "$RUNTIME_DIR"
  {
    echo '# DNSGuard v1.1.1 -> v1.2.1 候选升级与回滚验收'
    echo
    echo "- Run ID: $RUN_ID"
    echo "- Baseline: $BASELINE_REF (真实 Git tag)"
    echo "- Candidate: $CURRENT_REF"
    echo '- Environment: isolated Docker container, loopback-only host port, temporary state and test secret'
    echo '- Production resources: not accessed'
    echo
    echo '| 项目 | 状态 | 证据 |'
    echo '|---|---|---|'
    for i in "${!NAMES[@]}"; do
      echo "| ${NAMES[$i]} | ${STATUS[$i]} | \`${EVIDENCE[$i]}\` |"
    done
    echo
    echo '## 证据边界'
    echo
    echo '- PASS 仅表示该用例在本次隔离 Docker 环境真实执行。'
    echo '- 快照回滚恢复的是升级前副本，不把候选新格式反向兼容到旧版本。'
    echo '- 未读取或提交真实 Token、TSIG、TLS 私钥。'
  } >"$REPORT"
}

prepare_state() {
  local state="$RUNTIME_DIR/data"
  mkdir -p "$state" "$RUNTIME_DIR/secrets" "$RUNTIME_DIR/images"
  python3 - "$state" <<'PY'
import bcrypt, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
password = b"upgrade-test-password-2026"
auth = {"username":"admin", "passwordHash":bcrypt.hashpw(password, bcrypt.gensalt()).decode(), "mustChangePassword":False}
(root / "auth.json").write_text(json.dumps(auth, indent=2) + "\n")
state = {
  "nodes":[
    {"id":"primary-1","name":"isolated-primary","role":"primary","address":"198.51.100.10:53","status":"healthy","rpzVersion":"13","lastSync":"2026-11-07T00:00:00Z"},
    {"id":"secondary-1","name":"isolated-secondary","role":"secondary","address":"198.51.100.11:53","status":"healthy","rpzVersion":"13","lastSync":"2026-11-07T00:00:00Z"}
  ],
  "rules":[
    {"id":"rule-published","domain":"allowed.example.com","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"upgrade fixture","status":"published","updatedAt":"2026-11-07T00:00:00Z"},
    {"id":"rule-draft","domain":"draft.example.com","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"upgrade fixture","status":"draft","updatedAt":"2026-11-07T00:00:00Z"}
  ],
  "published":[{"id":"rule-published","domain":"allowed.example.com","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"upgrade fixture","status":"published","updatedAt":"2026-11-07T00:00:00Z"}],
  "versions":[{"id":"version-v111","createdAt":"2026-11-07T00:00:00Z","mode":"global","rules":[{"id":"rule-published","domain":"allowed.example.com","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"upgrade fixture","status":"published","updatedAt":"2026-11-07T00:00:00Z"}]}],
  "rulesRevision":7,"policyMode":"global"
}
(root / "dns-state.json").write_text(json.dumps(state, indent=2) + "\n")
(root / "dns-nodes.json").write_text(json.dumps(state["nodes"], indent=2) + "\n")
(root / "initialization.json").write_text(json.dumps({"status":"completed","version":1,"completedAt":"2026-11-07T00:00:00Z","username":"admin","zone":"rpz.local","primary":"198.51.100.10:53","secondaryCount":1,"policyMode":"global","deploymentCompleted":True,"deploymentCompletedAt":"2026-11-07T00:00:00Z"}, indent=2) + "\n")
audit = {"timestamp":"2026-11-07T00:00:00Z","actor":"admin","action":"setup.complete","result":"upgrade-fixture"}
payload = json.dumps(audit, separators=(",", ":"), ensure_ascii=False).encode()
audit["hash"] = __import__("hashlib").sha256(payload).hexdigest()
(root / "audit.json").write_text(json.dumps([audit], indent=2) + "\n")
(root / "publish-jobs.json").write_text("[]\n")
(root / "tld-state.json").write_text(json.dumps({"status":"ready","version":"fixture-1","tldCount":2}, indent=2) + "\n")
for p in root.iterdir(): p.chmod(0o600)
PY
  printf 'key "rpz-manager" { algorithm hmac-sha256; secret "upgrade-test-secret-only"; };\n' >"$RUNTIME_DIR/secrets/rpz-manager.key"
  chmod 0600 "$RUNTIME_DIR/secrets/rpz-manager.key"
  printf 'upgrade-test-bootstrap-token-only\n' >"$RUNTIME_DIR/secrets/bootstrap.token"
  chmod 0600 "$RUNTIME_DIR/secrets/bootstrap.token"
  # Keep the fixture private. The container is started with the current
  # isolated runner uid so rootless CI and bind-mounted state have identical
  # read/write semantics without requiring chown or elevated permissions.
  chmod 0700 "$RUNTIME_DIR/data" "$RUNTIME_DIR/secrets"
}

build_images() {
  local old_src="$RUNTIME_DIR/src-v111"
  mkdir -p "$old_src"
  git archive --format=tar "$BASELINE_REF" | tar -xf - -C "$old_src"
  git -C "$ROOT_DIR" rev-parse "$BASELINE_REF^{commit}" >"$RUNTIME_DIR/baseline.sha"
  git -C "$ROOT_DIR" rev-parse "$CURRENT_REF^{commit}" >"$RUNTIME_DIR/candidate.sha"
  docker build --quiet --target api -t "$OLD_IMAGE" "$old_src" >"$RUNTIME_DIR/build-old.log"
  docker build --quiet --target api -t "$NEW_IMAGE" "$ROOT_DIR" >"$RUNTIME_DIR/build-new.log"
}

env_file() {
  local file="$RUNTIME_DIR/$1.env"
  cat >"$file" <<EOF
APP_ENV=development
AUTH_ENABLED=true
AUTH_SECRET=upgrade-test-auth-secret-012345678901234567890123456789
MONITORING_TOKEN=upgrade-test-monitoring-token-012345678901234567890
AUTH_FILE=/var/lib/dnsguard/auth.json
DNS_NODE_CONFIG_FILE=/var/lib/dnsguard/dns-nodes.json
INITIALIZATION_FILE=/var/lib/dnsguard/initialization.json
DNS_STATE_FILE=/var/lib/dnsguard/dns-state.json
AUDIT_FILE=/var/lib/dnsguard/audit.json
RPZ_PUBLISH_JOBS_FILE=/var/lib/dnsguard/publish-jobs.json
TLD_STATE_FILE=/var/lib/dnsguard/tld-state.json
RPZ_ARTIFACT_FILE=/var/lib/dnsguard/rpz.local.db
RPZ_DEFAULT_DENY_MODE=global
RPZ_GLOBAL_DENY_ZONE=global-deny.rpz.local
RPZ_GLOBAL_DENY_SETUP_DEFERRED=true
DNS_NODE_ALLOWED_CIDRS=198.51.100.0/24
LISTEN_ADDR=0.0.0.0:8080
EOF
  printf '%s' "$file"
}

start_api() {
  local image="$1" container="$2" env="$3"
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker run -d --name "$container" --user "$(id -u):$(id -g)" --network "$NETWORK" -p "127.0.0.1:${PORT}:8080" \
    --label "com.dnsguard.test.run=$RUN_ID" \
    --env-file "$env" \
    -v "$RUNTIME_DIR/data:/var/lib/dnsguard" \
    -v "$RUNTIME_DIR/secrets:/run/dnsguard-secrets:ro" \
    "$image" >/dev/null
  for _ in $(seq 1 60); do
    curl -fsS "$BASE_URL/api/health" >/dev/null 2>&1 && return 0
    sleep 0.25
  done
  docker logs "$container" >&2
  return 1
}

login_and_read() {
  local label="$1" out cookie captcha_json captcha_id captcha_svg captcha_code
  out="$RUNTIME_DIR/$label-login.json"
  cookie="$RUNTIME_DIR/$label.cookie"
  captcha_json="$(curl -fsS "$BASE_URL/api/auth/captcha")"
  captcha_id="$(printf '%s' "$captcha_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
  captcha_svg="$(printf '%s' "$captcha_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["svg"])')"
  captcha_code="$(python3 - "$ROOT_DIR/server/captcha.go" "$captcha_svg" <<'PY'
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
        raise SystemExit(f'captcha glyph {index} ambiguous: {matches!r}')
    answer.append(matches[0])
print(''.join(answer))
PY
  )"
  curl -fsS -c "$cookie" -b "$cookie" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"upgrade-test-password-2026\",\"captchaId\":\"$captcha_id\",\"captcha\":\"$captcha_code\"}" \
    "$BASE_URL/api/auth/login" >"$out"
  curl -fsS -b "$cookie" "$BASE_URL/api/auth/me" >"$RUNTIME_DIR/$label-me.json"
  curl -fsS -b "$cookie" "$BASE_URL/api/dns/overview" >"$RUNTIME_DIR/$label-overview.json"
  curl -fsS -b "$cookie" "$BASE_URL/api/dns/rpz" >"$RUNTIME_DIR/$label-rules.json"
  curl -fsS -b "$cookie" "$BASE_URL/api/dns/rpz/versions" >"$RUNTIME_DIR/$label-versions.json"
  curl -fsS -b "$cookie" "$BASE_URL/api/audit" >"$RUNTIME_DIR/$label-audit.json"
  grep -q 'allowed.example.com' "$RUNTIME_DIR/$label-rules.json"
  grep -q 'version-v111' "$RUNTIME_DIR/$label-versions.json"
}

case_baseline() {
  [[ -f "$RUNTIME_DIR/baseline.sha" ]]
  sha256sum "$RUNTIME_DIR/data"/*.json >"$RUNTIME_DIR/pre-upgrade.sha256"
  start_api "$OLD_IMAGE" "$OLD_CONTAINER" "$(env_file old)"
  login_and_read old
  grep -q 'authenticated":true' "$RUNTIME_DIR/old-login.json"
  grep -q 'allowed.example.com' "$RUNTIME_DIR/old-rules.json"
  grep -q 'upgrade-fixture' "$RUNTIME_DIR/old-audit.json"
  cp -a "$RUNTIME_DIR/data" "$RUNTIME_DIR/snapshot-pre-upgrade"
  docker rm -f "$OLD_CONTAINER" >/dev/null
  echo "v1.1.1 baseline=$(cat "$RUNTIME_DIR/baseline.sha") data and login/history verified"
}

case_upgrade() {
  docker rm -f "$OLD_CONTAINER" "$NEW_CONTAINER" >/dev/null 2>&1 || true
  start_api "$NEW_IMAGE" "$NEW_CONTAINER" "$(env_file new)"
  login_and_read new
  grep -q 'allowed.example.com' "$RUNTIME_DIR/new-rules.json"
  grep -q 'draft.example.com' "$RUNTIME_DIR/new-rules.json"
  grep -q 'version-v111' "$RUNTIME_DIR/new-versions.json"
  grep -q 'upgrade-fixture' "$RUNTIME_DIR/new-audit.json"
  sha256sum "$RUNTIME_DIR/data"/*.json >"$RUNTIME_DIR/post-upgrade.sha256"
  grep -q 'initialization.json' "$RUNTIME_DIR/post-upgrade.sha256"
  echo "candidate=$(cat "$RUNTIME_DIR/candidate.sha") login, initialization, rules, draft, version, audit and config persisted"
}

case_interrupted_upgrade() {
  docker kill "$NEW_CONTAINER" >/dev/null
  grep -q 'allowed.example.com' "$RUNTIME_DIR/data/dns-state.json"
  [[ -d "$RUNTIME_DIR/snapshot-pre-upgrade" ]]
  start_api "$NEW_IMAGE" "$NEW_CONTAINER" "$(env_file new)"
  login_and_read new-restart
  grep -q 'version-v111' "$RUNTIME_DIR/new-restart-versions.json"
  echo 'candidate interruption and restart preserved the durable snapshot without claiming a migration rollback'
}

case_restore_old() {
  docker rm -f "$NEW_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$RUNTIME_DIR/data"
  cp -a "$RUNTIME_DIR/snapshot-pre-upgrade" "$RUNTIME_DIR/data"
  start_api "$OLD_IMAGE" "$OLD_CONTAINER" "$(env_file old)"
  login_and_read old-restore
  grep -q 'allowed.example.com' "$RUNTIME_DIR/old-restore-rules.json"
  grep -q 'version-v111' "$RUNTIME_DIR/old-restore-versions.json"
  cmp -s "$RUNTIME_DIR/data/dns-state.json" "$RUNTIME_DIR/snapshot-pre-upgrade/dns-state.json"
  sha256sum "$RUNTIME_DIR/data"/*.json >"$RUNTIME_DIR/post-restore.sha256"
  echo 'restored pre-upgrade snapshot and verified v1.1.1 login, rules, versions and state'
}

main() {
  for tool in docker curl git python3 sha256sum; do need "$tool"; done
  docker info >/dev/null
  git -C "$ROOT_DIR" rev-parse --verify "$BASELINE_REF^{commit}" >/dev/null
  git -C "$ROOT_DIR" rev-parse --verify "$CURRENT_REF^{commit}" >/dev/null
  mkdir -p "$RUNTIME_DIR"
  trap cleanup EXIT
  docker network create --label "com.dnsguard.test.run=$RUN_ID" "$NETWORK" >/dev/null
  prepare_state
  build_images
  run_case 'v1.1.1-baseline-login-and-history' case_baseline
  run_case 'candidate-upgrade-preserves-state' case_upgrade
  run_case 'interrupted-upgrade-fails-safe' case_interrupted_upgrade
  run_case 'snapshot-restore-to-v1.1.1' case_restore_old
  write_report
  if printf '%s\n' "${STATUS[@]}" | grep -q '^FAIL$'; then return 1; fi
}

main
