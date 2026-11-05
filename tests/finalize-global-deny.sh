#!/usr/bin/env bash
# Focused regression tests for scripts/finalize-global-deny.sh.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FINALIZE="$ROOT/scripts/finalize-global-deny.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

make_env() {
  local dir="$1" deferred="$2" env_file
  env_file="$dir/dnsguard.env"
  mkdir -p "$dir/data" "$dir/secrets" "$dir/tls" "$dir/logs"
  cat >"$env_file" <<ENV
DNSGUARD_DATA_DIR=$dir/data
DNSGUARD_SECRET_DIR=$dir/secrets
DNSGUARD_TLS_DIR=$dir/tls
DNSGUARD_BIND_LOG_DIR=$dir/logs
DNS_STATE_FILE=/var/lib/dnsguard/dns-state.json
RPZ_PUBLISH_JOBS_FILE=/var/lib/dnsguard/publish-jobs.json
RPZ_GLOBAL_DENY_BASELINE_FILE=/var/lib/dnsguard/global-deny-baseline.json
RPZ_GLOBAL_DENY_ZONE=global-deny.rpz.local
RPZ_GLOBAL_DENY_RECURSOR=192.0.2.10:53
RPZ_GLOBAL_DENY_CHECK_NAME=baseline.example.test
RPZ_GLOBAL_DENY_SETUP_DEFERRED=$deferred
DNSGUARD_INTERNAL_NETWORK_NAME=dnsguard-test-internal
ENV
  chmod 0640 "$env_file"
  printf '%s\n' "$env_file"
}

# Custom DNSGUARD_ENV_FILE and an empty state must fail before any env mutation.
EMPTY_DIR="$TMP/empty"
EMPTY_ENV="$(make_env "$EMPTY_DIR" true)"
cp -p "$EMPTY_ENV" "$EMPTY_ENV.before"
if DNSGUARD_ENV_FILE="$EMPTY_ENV" "$FINALIZE" >"$TMP/empty.log" 2>&1; then
  fail 'empty whitelist state unexpectedly passed'
fi
grep -Eq '白名单|DNS 状态文件' "$TMP/empty.log" || fail 'empty-state failure did not explain the blocked prerequisite'
cmp -s "$EMPTY_ENV" "$EMPTY_ENV.before" || fail 'failed preflight changed the env file'
pass 'custom DNSGUARD_ENV_FILE and unpublished whitelist are fail-closed'

# A Secondary sync exception must stop the script with a retry hint.
PENDING_DIR="$TMP/pending"
PENDING_ENV="$(make_env "$PENDING_DIR" true)"
cat >"$PENDING_DIR/data/dns-state.json" <<'JSON'
{"nodes":[{"id":"primary-1","role":"primary","address":"192.0.2.10:53"},{"id":"secondary-1","role":"secondary","address":"192.0.2.11:53"}],"rules":[{"domain":"allow.example.test","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"test"}],"published":[{"domain":"allow.example.test","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"test"}]}
JSON
cat >"$PENDING_DIR/data/publish-jobs.json" <<'JSON'
[{"id":"job-1","status":"succeeded","syncStatus":"published","createdAt":"2026-11-05T00:00:00Z","nodeChecks":[{"id":"primary-1","role":"primary","address":"192.0.2.10:53","status":"verified"},{"id":"secondary-1","role":"secondary","address":"192.0.2.11:53","status":"sync_exception"}]}]
JSON
if DNSGUARD_ENV_FILE="$PENDING_ENV" "$FINALIZE" >"$TMP/pending.log" 2>&1; then
  fail 'Secondary sync exception unexpectedly passed'
fi
grep -Eq '等待同步后重试|未验证' "$TMP/pending.log" || fail 'Secondary failure did not include retry guidance'
pass 'Secondary sync failure blocks finalization and recommends retry'

# Simulate a complete preflight with a failing docker compose recreation. The
# env must be atomically changed, a protected backup must exist, and the
# script must return non-zero with recovery guidance.
FAIL_DIR="$TMP/recreate-failure"
FAIL_ENV="$(make_env "$FAIL_DIR" true)"
cat >"$FAIL_DIR/data/dns-state.json" <<'JSON'
{"nodes":[{"id":"primary-1","role":"primary","address":"192.0.2.10:53"},{"id":"secondary-1","role":"secondary","address":"192.0.2.11:53"}],"rules":[{"domain":"allow.example.test","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"test"}],"published":[{"domain":"allow.example.test","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"test"}]}
JSON
cat >"$FAIL_DIR/data/publish-jobs.json" <<'JSON'
[{"id":"job-1","status":"succeeded","syncStatus":"published","createdAt":"2026-11-05T00:00:00Z","nodeChecks":[{"id":"primary-1","role":"primary","address":"192.0.2.10:53","status":"verified"},{"id":"secondary-1","role":"secondary","address":"192.0.2.11:53","status":"verified"}]}]
JSON
cat >"$FAIL_DIR/data/global-deny-baseline.json" <<'JSON'
{"checkName":"baseline.example.test","recursor":"192.0.2.10:53","rcode":"NOERROR","observedAt":"2026-11-05T00:00:00Z"}
JSON
FAKE_BIN="$TMP/fake-bin"
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/docker" <<'FAKE'
#!/usr/bin/env bash
set -u
if [[ "${1:-}" == compose ]]; then
  joined="$*"
  if [[ "$joined" == *' version'* ]]; then exit 0; fi
  if [[ "$joined" == *' config'* ]]; then exit 0; fi
  if [[ "$joined" == *' ps -q'* ]]; then printf 'fake-api\n'; exit 0; fi
  if [[ "$joined" == *' up '* ]]; then exit 42; fi
  exit 0
fi
if [[ "${1:-}" == inspect ]]; then
  format="${3:-${2:-}}"
  if [[ "$format" == *'State.Status'* ]]; then printf 'running\n'; exit 0; fi
  if [[ "$format" == *'Config.Env'* ]]; then printf 'RPZ_GLOBAL_DENY_SETUP_DEFERRED=true\n'; exit 0; fi
  if [[ "$format" == *'Health.Status'* ]]; then printf 'healthy\n'; exit 0; fi
  exit 0
fi
if [[ "${1:-}" == exec ]]; then
  shift 2
  has_soa=0
  has_cname=0
  for arg in "$@"; do
    [[ "$arg" == SOA ]] && has_soa=1
    [[ "$arg" == CNAME ]] && has_cname=1
  done
  if ((has_soa)); then printf 'ns.example. host.example. 7 3600 900 2592000 60\n'; exit 0; fi
  if ((has_cname)); then
    printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n'
    printf ';; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n'
    printf ';; ANSWER SECTION:\n*.global-deny.rpz.local. 60 IN CNAME .\n'
    exit 0
  fi
  printf ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n'
  exit 0
fi
exit 0
FAKE
chmod 0755 "$FAKE_BIN/docker"
if PATH="$FAKE_BIN:$PATH" DNSGUARD_ENV_FILE="$FAIL_ENV" "$FINALIZE" >"$TMP/recreate-failure.log" 2>&1; then
  fail 'API recreation failure unexpectedly passed'
fi
grep -q 'API 重建失败' "$TMP/recreate-failure.log" || { cat "$TMP/recreate-failure.log" >&2; fail 'API failure did not produce recovery guidance'; }
[[ "$(grep -E '^RPZ_GLOBAL_DENY_SETUP_DEFERRED=' "$FAIL_ENV")" == 'RPZ_GLOBAL_DENY_SETUP_DEFERRED=false' ]] || fail 'env was not atomically switched before recreation'
backup_count="$(find "$FAIL_DIR" -maxdepth 1 -name 'dnsguard.env.before-global-deny.*' | wc -l)"
[[ "$backup_count" -eq 1 ]] || fail 'protected env backup was not retained'
pass 'API recreation failure is non-zero, preserves backup, and prints recovery guidance'

printf 'All finalize-global-deny shell tests passed.\n'
