#!/usr/bin/env bash
# Focused regression tests for install.sh preflight and failure recovery.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dnsguard-install-preflight.XXXXXX")"
cleanup() {
  python3 -c 'from pathlib import Path; import shutil, sys; shutil.rmtree(Path(sys.argv[1]), ignore_errors=True)' "$WORK"
}
trap cleanup EXIT

INSTALL="$ROOT/install.sh"
FAKE_BIN="$WORK/bin"
mkdir -p "$FAKE_BIN"

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cat >"$FAKE_BIN/docker" <<'EOF'
#!/usr/bin/env bash
set -u
if [[ "${1:-}" == info && "${FAKE_DOCKER_INFO_FAIL:-0}" == 1 ]]; then
  exit 1
fi
exit 0
EOF
chmod 0755 "$FAKE_BIN/docker"

cat >"$FAKE_BIN/dig" <<'EOF'
#!/usr/bin/env bash
if [[ "${FAKE_DIG_BASELINE_FAIL:-0}" == 1 ]]; then
  printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1'
  printf '%s\n' ';; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0'
else
  printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1'
  printf '%s\n' ';; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0'
  printf '%s\n' ';; ANSWER SECTION:'
  printf '%s\n' 'baseline.example.test. 60 IN A 192.0.2.10'
fi
EOF
chmod 0755 "$FAKE_BIN/dig"

make_sources() {
  local dir="$1"
  mkdir -p "$dir"
  printf '%s\n' 'key "rpz-manager" { algorithm hmac-sha256; secret "fixture-only"; };' >"$dir/rpz-manager.key"
  chmod 0600 "$dir/rpz-manager.key"
  printf '%s\n' 'certificate fixture' >"$dir/fullchain.pem"
  printf '%s\n' 'private-key fixture' >"$dir/privkey.pem"
  chmod 0644 "$dir/fullchain.pem"
  chmod 0600 "$dir/privkey.pem"
}

run_expect_fail() {
  local log="$1"; shift
  set +e
  "$@" >"$log" 2>&1
  local code=$?
  set -e
  ((code != 0)) || { cat "$log" >&2; return 1; }
}

run_expect_fail_notty() {
  local log="$1"; shift
  set +e
  "$@" </dev/null >"$log" 2>&1
  local code=$?
  set -e
  ((code != 0)) || { cat "$log" >&2; return 1; }
}

# 1. No TTY and no BIND parameters must still reach the platform-first path;
#    the first missing requirement is the trusted HTTPS certificate, not BIND.
NO_TTY_ENV="$WORK/no-tty.env"
NO_TTY_LOG="$WORK/no-tty.log"
run_expect_fail_notty "$NO_TTY_LOG" env PATH="$FAKE_BIN:$PATH" \
  DNSGUARD_ENV_FILE="$NO_TTY_ENV" \
  DNSGUARD_DATA_DIR="$WORK/no-tty-data" \
  DNSGUARD_SECRET_DIR="$WORK/no-tty-secrets" \
  DNSGUARD_TLS_DIR="$WORK/no-tty-tls" \
  DNSGUARD_BIND_LOG_DIR="$WORK/no-tty-logs" "$INSTALL"
grep -q 'HTTPS 证书' "$NO_TTY_LOG" || fail 'platform-first error omitted HTTPS certificate guidance'
if grep -q 'BIND Primary 地址' "$NO_TTY_LOG"; then fail 'platform-first install still requires BIND before startup'; fi
[[ ! -e "$NO_TTY_ENV" ]] || fail 'non-interactive missing-input path created env'
pass 'non-interactive missing inputs are explicit and non-zero'

# 1b. A fresh platform-first install needs only protected HTTPS material and
#     does not create or validate a TSIG/BIND configuration.
PLATFORM_DIR="$WORK/platform"
PLATFORM_SOURCES="$WORK/platform-sources"
mkdir -p "$PLATFORM_DIR" "$PLATFORM_SOURCES"
printf '%s\n' 'certificate fixture' >"$PLATFORM_SOURCES/fullchain.pem"
printf '%s\n' 'private-key fixture' >"$PLATFORM_SOURCES/privkey.pem"
chmod 0644 "$PLATFORM_SOURCES/fullchain.pem"; chmod 0600 "$PLATFORM_SOURCES/privkey.pem"
env PATH="$FAKE_BIN:$PATH" \
  DNSGUARD_ENV_FILE="$PLATFORM_DIR/dnsguard.env" \
  DNSGUARD_DATA_DIR="$PLATFORM_DIR/data" \
  DNSGUARD_SECRET_DIR="$PLATFORM_DIR/secrets" \
  DNSGUARD_TLS_DIR="$PLATFORM_DIR/tls" \
  DNSGUARD_BIND_LOG_DIR="$PLATFORM_DIR/logs" \
  TLS_CERT_SOURCE="$PLATFORM_SOURCES/fullchain.pem" TLS_KEY_SOURCE="$PLATFORM_SOURCES/privkey.pem" "$INSTALL" >"$WORK/platform.log" 2>&1 || {
    cat "$WORK/platform.log" >&2
    fail 'platform-first install failed without BIND or TSIG'
  }
grep -q 'DNSGUARD_PLATFORM_ONLY=true' "$PLATFORM_DIR/dnsguard.env" || fail 'platform-first env flag missing'
[[ ! -e "$PLATFORM_DIR/secrets/rpz-manager.key" ]] || fail 'platform-first install unexpectedly created a TSIG key'
cp -p "$PLATFORM_DIR/dnsguard.env" "$WORK/platform.env.before"
cp -p "$PLATFORM_DIR/secrets/bootstrap.token" "$WORK/platform.token.before"
env PATH="$FAKE_BIN:$PATH" DNSGUARD_ENV_FILE="$PLATFORM_DIR/dnsguard.env" "$INSTALL" >"$WORK/platform-repeat.log" 2>&1 || {
  cat "$WORK/platform-repeat.log" >&2
  fail 'repeated platform-first install failed'
}
cmp -s "$PLATFORM_DIR/dnsguard.env" "$WORK/platform.env.before" || fail 'repeated install overwrote platform env'
cmp -s "$PLATFORM_DIR/secrets/bootstrap.token" "$WORK/platform.token.before" || fail 'repeated install overwrote Bootstrap Token'
pass 'platform-first install starts with HTTPS only and defers BIND/TSIG'

# 2. Docker Compose can be present while the Engine is inaccessible.
DOCKER_LOG="$WORK/docker.log"
run_expect_fail_notty "$DOCKER_LOG" env PATH="$FAKE_BIN:$PATH" FAKE_DOCKER_INFO_FAIL=1 \
  DNSGUARD_ENV_FILE="$WORK/docker.env" "$INSTALL"
grep -Eq 'Docker Engine|Docker Socket' "$DOCKER_LOG" || fail 'Docker access failure lacked remediation'
pass 'Docker Engine access is checked separately from Compose version'

# 3. Failed baseline must not create a new env or data directories.
BASELINE_ENV="$WORK/baseline.env"
BASELINE_LOG="$WORK/baseline.log"
SOURCES="$WORK/sources"
make_sources "$SOURCES"
run_expect_fail_notty "$BASELINE_LOG" env PATH="$FAKE_BIN:$PATH" FAKE_DIG_BASELINE_FAIL=1 \
  DNSGUARD_PLATFORM_ONLY=false \
  DNSGUARD_ENV_FILE="$BASELINE_ENV" \
  DNSGUARD_DATA_DIR="$WORK/baseline-data" \
  DNSGUARD_SECRET_DIR="$WORK/baseline-secrets" \
  DNSGUARD_TLS_DIR="$WORK/baseline-tls" \
  DNSGUARD_BIND_LOG_DIR="$WORK/baseline-logs" \
  RPZ_PRIMARY=192.0.2.10 RPZ_GLOBAL_DENY_RECURSOR=192.0.2.10:53 \
  RPZ_GLOBAL_DENY_CHECK_NAME=baseline.example.test \
  RPZ_TSIG_SOURCE="$SOURCES/rpz-manager.key" \
  TLS_CERT_SOURCE="$SOURCES/fullchain.pem" TLS_KEY_SOURCE="$SOURCES/privkey.pem" "$INSTALL"
grep -q '正常解析基线' "$BASELINE_LOG" || fail 'baseline failure lacked explanation'
[[ ! -e "$BASELINE_ENV" ]] || fail 'baseline failure created env'
[[ ! -e "$WORK/baseline-data" && ! -e "$WORK/baseline-secrets" && ! -e "$WORK/baseline-tls" ]] || fail 'baseline failure created deployment directories'
pass 'failed baseline leaves no new env or deployment directories'

# 4. An existing env is never overwritten when a later preflight fails.
EXISTING_DIR="$WORK/existing"
mkdir -p "$EXISTING_DIR/data" "$EXISTING_DIR/secrets" "$EXISTING_DIR/tls" "$EXISTING_DIR/logs"
make_sources "$EXISTING_DIR/source"
cp "$EXISTING_DIR/source/rpz-manager.key" "$EXISTING_DIR/secrets/rpz-manager.key"
cp "$EXISTING_DIR/source/fullchain.pem" "$EXISTING_DIR/tls/fullchain.pem"
cp "$EXISTING_DIR/source/privkey.pem" "$EXISTING_DIR/tls/privkey.pem"
chmod 0640 "$EXISTING_DIR/secrets/rpz-manager.key" "$EXISTING_DIR/tls/privkey.pem"
cat >"$EXISTING_DIR/dnsguard.env" <<ENV
DNSGUARD_DATA_DIR=$EXISTING_DIR/data
DNSGUARD_SECRET_DIR=$EXISTING_DIR/secrets
DNSGUARD_TLS_DIR=$EXISTING_DIR/tls
DNSGUARD_BIND_LOG_DIR=$EXISTING_DIR/logs
APP_ENV=production
AUTH_ENABLED=true
AUTH_SECRET=existing-auth-secret-012345678901234567890123456789
MONITORING_TOKEN=existing-monitor-token-012345678901234567890123456789
RPZ_PRIMARY=192.0.2.10
RPZ_DEFAULT_DENY_MODE=global
RPZ_GLOBAL_DENY_RECURSOR=192.0.2.10:53
RPZ_GLOBAL_DENY_CHECK_NAME=baseline.example.test
RPZ_GLOBAL_DENY_SETUP_DEFERRED=true
ENV
chmod 0640 "$EXISTING_DIR/dnsguard.env"
cp -p "$EXISTING_DIR/dnsguard.env" "$EXISTING_DIR/dnsguard.env.before"
run_expect_fail_notty "$WORK/existing.log" env PATH="$FAKE_BIN:$PATH" FAKE_DIG_BASELINE_FAIL=1 \
  DNSGUARD_ENV_FILE="$EXISTING_DIR/dnsguard.env" "$INSTALL"
cmp -s "$EXISTING_DIR/dnsguard.env" "$EXISTING_DIR/dnsguard.env.before" || fail 'existing env was modified after preflight failure'
pass 'existing env remains unchanged after preflight failure'

# 5. Complete input path reaches the normal initialization path with a fake
# Docker command and preserves source-file modes.
SUCCESS_DIR="$WORK/success"
mkdir -p "$SUCCESS_DIR/data" "$SUCCESS_DIR/secrets" "$SUCCESS_DIR/tls" "$SUCCESS_DIR/logs"
make_sources "$SUCCESS_DIR/source"
cp "$SUCCESS_DIR/source/rpz-manager.key" "$SUCCESS_DIR/secrets/rpz-manager.key"
cp "$SUCCESS_DIR/source/fullchain.pem" "$SUCCESS_DIR/tls/fullchain.pem"
cp "$SUCCESS_DIR/source/privkey.pem" "$SUCCESS_DIR/tls/privkey.pem"
chmod 0640 "$SUCCESS_DIR/secrets/rpz-manager.key" "$SUCCESS_DIR/tls/privkey.pem"
cat >"$SUCCESS_DIR/dnsguard.env" <<ENV
DNSGUARD_DATA_DIR=$SUCCESS_DIR/data
DNSGUARD_SECRET_DIR=$SUCCESS_DIR/secrets
DNSGUARD_TLS_DIR=$SUCCESS_DIR/tls
DNSGUARD_BIND_LOG_DIR=$SUCCESS_DIR/logs
APP_ENV=production
AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_SECRET=success-auth-secret-012345678901234567890123456789
MONITORING_TOKEN=success-monitor-token-012345678901234567890123456789
RPZ_PRIMARY=192.0.2.10
RPZ_DEFAULT_DENY_MODE=legacy
ENV
chmod 0640 "$SUCCESS_DIR/dnsguard.env"
printf '%s\n' 'success-token-012345678901234567890123' >"$SUCCESS_DIR/secrets/bootstrap.token"
chmod 0600 "$SUCCESS_DIR/secrets/bootstrap.token"
before_key_mode="$(stat -c '%a' "$SUCCESS_DIR/source/rpz-manager.key")"
before_cert_mode="$(stat -c '%a' "$SUCCESS_DIR/source/fullchain.pem")"
before_tls_key_mode="$(stat -c '%a' "$SUCCESS_DIR/source/privkey.pem")"
env PATH="$FAKE_BIN:$PATH" DNSGUARD_ENV_FILE="$SUCCESS_DIR/dnsguard.env" "$INSTALL" >"$WORK/success.log" 2>&1 || {
  cat "$WORK/success.log" >&2
  fail 'complete-input path did not reach normal initialization'
}
[[ "$(stat -c '%a' "$SUCCESS_DIR/source/rpz-manager.key")" == "$before_key_mode" ]]
[[ "$(stat -c '%a' "$SUCCESS_DIR/source/fullchain.pem")" == "$before_cert_mode" ]]
[[ "$(stat -c '%a' "$SUCCESS_DIR/source/privkey.pem")" == "$before_tls_key_mode" ]]
[[ "$(stat -c '%a' "$SUCCESS_DIR/secrets/bootstrap.token")" == 600 ]]
pass 'complete-input path succeeds without lowering TSIG, TLS or Bootstrap permissions'

printf '%s\n' 'PASS: install preflight and recovery checks'
