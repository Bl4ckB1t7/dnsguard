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
cat >>"$NSUPDATE_LOG"
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
  *' SOA '*) printf '%s\n' 'rpz.local. hostmaster.local. 123 1h 15m 30d 60' ;;
  *) : ;;
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
