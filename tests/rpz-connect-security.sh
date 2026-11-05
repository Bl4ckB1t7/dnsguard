#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dnsguard-rpz-connect.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
KEY="$WORK/rpz.key"
printf '%s\n' 'key "rpz-manager" { algorithm hmac-sha256; secret "fixture"; };' >"$KEY"
chmod 0600 "$KEY"
NSUPDATE_LOG="$WORK/nsupdate.log"
export NSUPDATE_LOG
cat >"$WORK/bin/nsupdate" <<'EOF'
#!/usr/bin/env bash
input="$(cat)"
printf '%s\n' "$input" >>"$NSUPDATE_LOG"
if [[ "${NSUPDATE_MODE:-}" == signal && "$input" == *'update add '* ]]; then
  sleep 30
fi
if [[ "${NSUPDATE_MODE:-}" == cleanup-fail && "$input" == *'update delete '* ]]; then
  exit 1
fi
exit 0
EOF
chmod +x "$WORK/bin/nsupdate"

run_expect_fail() {
  local output code
  set +e
  output="$("$@" 2>&1)"
  code=$?
  set -e
  [[ "$code" -ne 0 ]] || { printf '%s\n' "$output" >&2; return 1; }
}

# A failed Primary/Secondary preflight must stop before nsupdate is invoked.
run_expect_fail env PATH="$WORK/bin:$PATH" \
  RPZ_ZONE=rpz.local RPZ_PRIMARY=127.0.0.1:9 RPZ_SECONDARIES=127.0.0.1:9 \
  RPZ_KEY_FILE="$KEY" RPZ_TEST_DOMAIN=business.example.com \
  "$ROOT/scripts/rpz-connect.sh" --write-test --confirm WRITE-TEST
[[ ! -s "$NSUPDATE_LOG" ]]
echo 'PASS: unreachable preflight prevented all writes'

# Use a deterministic fake read-only DNS response to exercise the write gate
# without contacting any BIND instance.
cat >"$WORK/bin/dig" <<'EOF'
#!/usr/bin/env bash
case " $* " in
  *'+short'*' SOA '*)
    printf '%s\n' 'localhost. hostmaster.localhost. 123 3600 900 2592000 60'
    ;;
  *' SOA '*)
    printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1' ';; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0' 'rpz.local. 60 IN SOA hostmaster.local. 123 1h 15m 30d 60'
    ;;
  *)
    printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1' ';; flags: qr aa; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0'
    ;;
esac
EOF
chmod +x "$WORK/bin/dig"
: >"$NSUPDATE_LOG"
run_expect_fail env PATH="$WORK/bin:$PATH" \
  RPZ_ZONE=rpz.local RPZ_PRIMARY=127.0.0.1:53 RPZ_SECONDARIES=127.0.0.2:53 \
  RPZ_KEY_FILE="$KEY" RPZ_TEST_DOMAIN=business.example.com \
  "$ROOT/scripts/rpz-connect.sh" --write-test --confirm WRITE-TEST
[[ ! -s "$NSUPDATE_LOG" ]]
echo 'PASS: custom business domain outside the protected namespace was rejected'

: >"$NSUPDATE_LOG"
run_expect_fail env PATH="$WORK/bin:$PATH" \
  RPZ_ZONE=rpz.local RPZ_PRIMARY=127.0.0.1:53 RPZ_SECONDARIES=127.0.0.2:53 \
  RPZ_KEY_FILE="$KEY" RPZ_TEST_DOMAIN=foo._dnsguard-preflight.rpz.local \
  "$ROOT/scripts/rpz-connect.sh" --write-test
[[ ! -s "$NSUPDATE_LOG" ]]
echo 'PASS: missing WRITE-TEST confirmation prevented writes'

: >"$NSUPDATE_LOG"
run_expect_fail env PATH="$WORK/bin:$PATH" \
  RPZ_ZONE=rpz.local RPZ_PRIMARY=127.0.0.1:53 RPZ_SECONDARIES=127.0.0.2:53 \
  RPZ_KEY_FILE="$KEY" RPZ_TEST_DOMAIN=foo._dnsguard-preflight.rpz.local \
  "$ROOT/scripts/rpz-connect.sh" --write-test --confirm WRITE-TEST
grep -q 'prereq nxdomain' "$NSUPDATE_LOG"
grep -q 'update add .* TXT "dnsguard-preflight-' "$NSUPDATE_LOG"
if grep -q '^update delete .* TXT$' "$NSUPDATE_LOG"; then
  echo 'broad TXT deletion was emitted' >&2
  exit 1
fi
echo 'PASS: only an in-scope confirmed test reached nsupdate with NXDOMAIN prerequisite and unique TXT RDATA'

# A successful UPDATE followed by a read-back timeout must still issue the
# exact cleanup UPDATE and return failure rather than claiming success.
cat >"$WORK/bin/dig" <<'EOF'
#!/usr/bin/env bash
case " $* " in
  *'+short'*' SOA '*) printf '%s\n' 'localhost. hostmaster.localhost. 123 3600 900 2592000 60' ;;
  *' SOA '*) printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1' ';; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0' ;;
  *' ANY '*) printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1' ';; flags: qr aa; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0' ;;
  *' TXT '*)
    if [[ "${NSUPDATE_MODE:-}" == cleanup-fail ]]; then
      printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1' ';; flags: qr aa; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0'
    else
      exit 1
    fi
    ;;
esac
EOF
chmod +x "$WORK/bin/dig"
: >"$NSUPDATE_LOG"
set +e
output="$(env PATH="$WORK/bin:$PATH" \
  RPZ_ZONE=rpz.local RPZ_PRIMARY=127.0.0.1:53 RPZ_SECONDARIES=127.0.0.2:53 \
  RPZ_KEY_FILE="$KEY" RPZ_TEST_DOMAIN=foo._dnsguard-preflight.rpz.local \
  "$ROOT/scripts/rpz-connect.sh" --write-test --confirm WRITE-TEST 2>&1)"
code=$?
set -e
[[ "$code" -ne 0 ]]
grep -q 'DNS 读回状态无法确认' <<<"$output"
grep -q 'update delete .* TXT "dnsguard-preflight-' "$NSUPDATE_LOG"
if grep -q '^update delete .* TXT$' "$NSUPDATE_LOG"; then
  echo 'cleanup emitted a broad TXT delete after a read-back timeout' >&2
  exit 1
fi
echo 'PASS: read-back timeout caused exact cleanup and a failed result'

# A cleanup UPDATE failure must remain a failure even if a follow-up query does
# not find the test record.  The result is still uncertain and needs manual
# reconciliation rather than being reported as a clean success.
: >"$NSUPDATE_LOG"
set +e
output="$(NSUPDATE_MODE=cleanup-fail env PATH="$WORK/bin:$PATH" \
  RPZ_ZONE=rpz.local RPZ_PRIMARY=127.0.0.1:53 RPZ_SECONDARIES=127.0.0.2:53 \
  RPZ_KEY_FILE="$KEY" RPZ_TEST_DOMAIN=foo._dnsguard-preflight.rpz.local \
  "$ROOT/scripts/rpz-connect.sh" --write-test --confirm WRITE-TEST 2>&1)"
code=$?
set -e
[[ "$code" -ne 0 ]]
grep -q '清理 UPDATE 返回失败' <<<"$output"
grep -q 'update delete .* TXT "dnsguard-preflight-' "$NSUPDATE_LOG"
echo 'PASS: cleanup UPDATE failure was not hidden by an empty follow-up query'

# If cleanup verification itself fails, the output must require manual
# reconciliation and must not expose the full random TXT token.
: >"$NSUPDATE_LOG"
set +e
output="$(env PATH="$WORK/bin:$PATH" \
  RPZ_ZONE=rpz.local RPZ_PRIMARY=127.0.0.1:53 RPZ_SECONDARIES=127.0.0.2:53 \
  RPZ_KEY_FILE="$KEY" RPZ_TEST_DOMAIN=foo._dnsguard-preflight.rpz.local \
  "$ROOT/scripts/rpz-connect.sh" --write-test --confirm WRITE-TEST 2>&1)"
code=$?
set -e
[[ "$code" -ne 0 ]]
grep -q '清理状态无法确认' <<<"$output"
grep -q '人工核对' <<<"$output"
if grep -Eq 'dnsguard-preflight-[0-9a-f]{24}' <<<"$output"; then
  echo 'full random TXT token leaked in cleanup diagnostics' >&2
  exit 1
fi
echo 'PASS: cleanup query failure entered manual reconciliation without leaking the full token'

# SIGTERM during nsupdate must stop the flow, run the EXIT cleanup trap, and
# never continue into another write operation.
cat >"$WORK/bin/dig" <<'EOF'
#!/usr/bin/env bash
case " $* " in
  *'+short'*' SOA '*) printf '%s\n' 'localhost. hostmaster.localhost. 123 3600 900 2592000 60' ;;
  *' SOA '*) printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1' ';; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0' ;;
  *) printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1' ';; flags: qr aa; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0' ;;
esac
EOF
chmod +x "$WORK/bin/dig"
: >"$NSUPDATE_LOG"
set +e
NSUPDATE_MODE=signal env PATH="$WORK/bin:$PATH" \
  RPZ_ZONE=rpz.local RPZ_PRIMARY=127.0.0.1:53 RPZ_SECONDARIES=127.0.0.2:53 \
  RPZ_KEY_FILE="$KEY" RPZ_TEST_DOMAIN=foo._dnsguard-preflight.rpz.local \
  "$ROOT/scripts/rpz-connect.sh" --write-test --confirm WRITE-TEST >"$WORK/signal.out" 2>&1 &
pid=$!
for _ in $(seq 1 30); do
  grep -q '^update add ' "$NSUPDATE_LOG" && break
  sleep 0.1
done
kill -TERM "$pid"
wait "$pid"
code=$?
set -e
[[ "$code" == 130 ]]
grep -q '^update add ' "$NSUPDATE_LOG"
grep -q '^update delete .* TXT "dnsguard-preflight-' "$NSUPDATE_LOG"
echo 'PASS: SIGTERM stopped the write flow and ran precise EXIT cleanup'

# Optional policy checks are explicit and must use a known baseline resolver
# plus an authoritative RPZ trigger witness. This is a mock test only; it does
# not claim that a production deny zone exists.
cat >"$WORK/bin/dig" <<'EOF_DIG'
#!/usr/bin/env bash
case " $* " in
  *'+short'*' SOA '*) printf '%s\n' 'localhost. hostmaster.localhost. 123 3600 900 2592000 60' ;;
  *' SOA '*) printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1' ';; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0' 'rpz.local. 60 IN SOA hostmaster.local. 123 1h 15m 30d 60' ;;
  *'known.example A '*) printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1' ';; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0' 'known.example. 60 IN A 192.0.2.123' ;;
  *'com.deny.rpz.local CNAME '*) printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1' ';; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0' 'com.deny.rpz.local. 60 IN CNAME .' ;;
  *'@127.0.0.2'*'denied.example A '*) printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1' ';; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0' 'denied.example. 60 IN A 192.0.2.123' ;;
  *'denied.example A '*) printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1' ';; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0' ;;
  *) printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1' ';; flags: qr aa; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0' ;;
esac
EOF_DIG
chmod +x "$WORK/bin/dig"
output="$(env PATH="$WORK/bin:$PATH" \
  RPZ_ZONE=rpz.local RPZ_PRIMARY=127.0.0.1:53 RPZ_SECONDARIES=127.0.0.2:53 \
  RPZ_KEY_FILE="$KEY" RPZ_RECURSOR=127.0.0.1:53 \
  RPZ_ALLOW_CHECK_NAME=known.example RPZ_ALLOW_EXPECTED_A=192.0.2.123 \
  RPZ_DENY_ZONE=deny.rpz.local RPZ_DENY_CHECK_NAME=denied.example \
  RPZ_DENY_TRIGGER=com.deny.rpz.local RPZ_DENY_BASELINE_RECURSOR=127.0.0.2:53 \
  RPZ_DENY_BASELINE_EXPECTED_A=192.0.2.123 \
  "$ROOT/scripts/rpz-connect.sh" 2>&1)"
grep -q '白名单递归验证 实际解析符合预期' <<<"$output"
grep -q '默认拒绝递归验证 RCODE 符合预期' <<<"$output"
grep -q '默认拒绝 RPZ 证据 已观察到 RPZ CNAME' <<<"$output"
echo 'PASS: optional allow-list and deny-policy checks require and verify explicit evidence'
