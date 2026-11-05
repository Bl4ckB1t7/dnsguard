#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEST_DIR="$ROOT_DIR/tests/bind-cluster/global-deny-experiment"
BASE_RUN="$TEST_DIR/run.sh"
COMPOSE_FILE="$TEST_DIR/compose.yaml"
PROJECT="dnsguard-global-deny-experiment"
MODE="${QNAME_WAIT_RECURSE:-no}"
FAILURES=0

case "$MODE" in
  default|yes|no) ;;
  *) echo 'QNAME_WAIT_RECURSE must be default, yes, or no' >&2; exit 2 ;;
esac

compose() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
pass() { printf 'PASS  %s\n' "$*"; }

for tool in docker dig openssl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "NOT RUN: missing $tool" >&2; exit 125; }
done
docker info >/dev/null 2>&1 || { echo 'NOT RUN: Docker daemon unavailable' >&2; exit 125; }

# Start the same isolated BIND environment used by the RPZ experiment.  The
# base script may return 1 when it correctly detects the DNSSEC upstream leak;
# that is evidence for this workload, not a reason to skip the workload.
compose down --remove-orphans >/dev/null 2>&1 || true
set +e
QNAME_WAIT_RECURSE="$MODE" "$BASE_RUN" --keep >"/tmp/dnsguard-dns-tunnel-base-$MODE.log" 2>&1
base_rc=$?
set -e
if [[ ! -f "/tmp/dnsguard-dns-tunnel-base-$MODE.log" ]]; then
  echo 'NOT RUN: isolated BIND bootstrap did not produce a log' >&2
  exit 125
fi

container_for() {
  case "$1" in
    primary|secondary-1|secondary-2) printf 'dnsguard-global-deny-experiment-%s-1\n' "$1" ;;
    *) echo "unknown BIND service: $1" >&2; return 2 ;;
  esac
}

query_rcode() {
  local service="$1" name="$2" qtype="$3" dnssec="$4"
  local output
  local -a args=(@127.0.0.1 +tcp +time=2 +tries=1)
  [[ -n "$dnssec" ]] && args+=("$dnssec")
  args+=("$name" "$qtype" +noall +comments)
  output="$(docker exec "$(container_for "$service")" dig "${args[@]}" 2>&1)"
  printf '%s\n' "$output" | sed -n 's/.*status: \([^,]*\),.*/\1/p' | head -1
}

upstream_seen() {
  local name="$1"
  compose logs --no-color upstream 2>/dev/null | grep -F "($name)" >/dev/null 2>&1
}

readarray -t generated < <(python3 - <<'PY'
import secrets
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
base32 = ''.join(secrets.choice(alphabet) for _ in range(50))
hexd = secrets.token_hex(25)
chunk1 = ''.join(secrets.choice(alphabet) for _ in range(38))
chunk2 = ''.join(secrets.choice(alphabet) for _ in range(38))
chunk3 = ''.join(secrets.choice(alphabet) for _ in range(38))
session = secrets.token_hex(8)
print(base32)
print(hexd)
print(chunk1)
print(chunk2)
print(chunk3)
print(session)
PY
)
base32_label="${generated[0]}"
hex_label="${generated[1]}"
chunk1="${generated[2]}"
chunk2="${generated[3]}"
chunk3="${generated[4]}"
session="${generated[5]}"

names=(
  "${base32_label}.example.com"
  "${hex_label}.example.com"
  "${chunk1}.${chunk2}.${chunk3}.example.com"
  "${base32_label}.tunnel.example.com"
  "s${session}.d${hex_label}.example.com"
  "${base32_label}.dnssec.example.com"
)
types=(A TXT AAAA NULL TXT A)
dnssec=("" "" "" "" "" "+dnssec")
labels=(
  'iodine-like Base32 QNAME / A'
  'hex TXT chunk'
  'long multi-label AAAA chunks'
  'iodine-like NULL request'
  'dnscat-like session TXT chunk'
  'DNSSEC DO=1 Base32 QNAME'
)

printf 'MODE=%s BASE_BOOTSTRAP_EXIT=%s\n' "$MODE" "$base_rc"
for i in "${!names[@]}"; do
  name="${names[$i]}"
  type="${types[$i]}"
  rcode="$(query_rcode primary "$name" "$type" "${dnssec[$i]}")"
  if [[ "$rcode" == NXDOMAIN ]]; then
    pass "${labels[$i]} returned NXDOMAIN"
  else
    fail "${labels[$i]} returned $rcode instead of NXDOMAIN"
  fi
  if upstream_seen "$name"; then
    fail "${labels[$i]} reached upstream with full QNAME"
  else
    pass "${labels[$i]} did not reach simulated upstream"
  fi
done

# Confirm the same ordinary tunnel shapes are blocked on both secondaries.
for service in secondary-1 secondary-2; do
  service_label="${service//-/}"
  for name in "${base32_label}.${service_label}.example.com" "s${session}.d${hex_label}.${service_label}.example.com"; do
    rcode="$(query_rcode "$service" "$name" A '')"
    if [[ "$rcode" == NXDOMAIN ]]; then
      pass "$service returned NXDOMAIN for representative tunnel QNAME"
    else
      fail "$service returned $rcode for representative tunnel QNAME"
    fi
    if upstream_seen "$name"; then
      fail "$service representative tunnel QNAME reached simulated upstream"
    else
      pass "$service representative tunnel QNAME did not reach simulated upstream"
    fi
  done
done

if ((FAILURES)); then
  exit 1
fi
pass 'DNS tunnel workload completed'
