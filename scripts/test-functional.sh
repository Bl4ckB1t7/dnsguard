#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://127.0.0.1:8080}"
PRIMARY="${PRIMARY:-127.0.0.2}"
SECONDARIES=("${SECONDARY_1:-127.0.0.3}" "${SECONDARY_2:-127.0.0.4}")
DNS_PORT="${DNS_PORT:-5353}"
KEY_FILE="${RPZ_KEY_FILE:-$PWD/dns-lab/keys/rpz-manager.key}"
NODE_CONFIG_FILE="${DNS_NODE_CONFIG_FILE:-$PWD/config/dns-nodes.json}"
ZONE="${RPZ_ZONE:-rpz.local}"
TEST_DOMAIN="functional-$(date +%s%N).example.com"
RULE_ID=""
PUBLISH_JOB_ID=""
BULK_IDS=()
PASSED=0

pass() {
  PASSED=$((PASSED + 1))
  printf 'PASS: %s\n' "$1"
}

cleanup() {
  if ((${#BULK_IDS[@]} > 0)); then
    bulk_json=$(printf '%s\n' "${BULK_IDS[@]}" | python3 -c 'import json,sys; print(json.dumps([line.strip() for line in sys.stdin if line.strip()]))')
    curl -fsS -H 'Content-Type: application/json' -d "{\"ids\":$bulk_json}" "$API_URL/api/dns/rpz/bulk" >/dev/null || true
  fi
  if [[ -n "$RULE_ID" ]]; then
    curl -fsS -X DELETE "$API_URL/api/dns/rpz/$RULE_ID" >/dev/null || true
    PUBLISH_JOB_ID=$(curl -fsS -X POST "$API_URL/api/dns/rpz/publish" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])') || true
    wait_publish_job || true
  fi
}
trap cleanup EXIT

wait_publish_job() {
  for _ in $(seq 1 60); do
    job=$(curl -fsS "$API_URL/api/dns/rpz/jobs/$PUBLISH_JOB_ID") || return 1
    status=$(printf '%s' "$job" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
    if [[ "$status" == "succeeded" ]]; then
      return 0
    fi
    if [[ "$status" == "failed" ]]; then
      printf '%s\n' "$job" >&2
      return 1
    fi
    sleep 0.25
  done
  return 1
}

curl -fsS "$API_URL/api/health" | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"] == "ok"'
pass "API health"

curl -fsS "$API_URL/api/settings" | python3 -c 'import json,sys; assert json.load(sys.stdin)["title"] == "DNS 解析控制中心"'
pass "settings"

curl -fsS "$API_URL/api/auth/me" | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["authenticated"] and x["authEnabled"] is False'
pass "authentication page disabled"

curl -fsS "$API_URL/api/dns/nodes" | python3 -c '
import json,sys
x=json.load(sys.stdin)
assert len(x) == 3
assert all(node["status"] == "healthy" for node in x), x
assert len({node["rpzVersion"] for node in x}) == 1, x
'
pass "live DNS node status and RPZ Serial comparison"

curl -fsS -H 'Content-Type: application/json' -d '{"id":"primary-1","address":"127.0.0.2:5353"}' "$API_URL/api/dns/nodes" | python3 -c 'import json,sys; assert json.load(sys.stdin)["updated"] is True'
python3 - "$NODE_CONFIG_FILE" <<'PY'
import json,sys
nodes=json.load(open(sys.argv[1]))
assert next(node for node in nodes if node["id"] == "primary-1")["address"] == "127.0.0.2:5353"
PY
pass "DNS node configuration persistence"

curl -fsS "$API_URL/api/dns/overview" | python3 -c '
import json,sys
x=json.load(sys.stdin)
assert x["rpzHitStatus"] == "ready"
assert isinstance(x["rpzHits"], int)
'
pass "real RPZ hit counter"

create_response=$(curl -fsS -H 'Content-Type: application/json' -d "{\"domain\":\"$TEST_DOMAIN\",\"reason\":\"functional test\"}" "$API_URL/api/dns/rpz")
RULE_ID=$(printf '%s' "$create_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl -fsS "$API_URL/api/dns/overview" | python3 -c 'import json,sys; assert json.load(sys.stdin)["pendingPublish"] is True'
pass "RPZ rule creation marks pending publish"

PUBLISH_JOB_ID=$(curl -fsS -X POST "$API_URL/api/dns/rpz/publish" | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["status"] == "queued"; print(x["id"])')
wait_publish_job
curl -fsS "$API_URL/api/dns/rpz/jobs/$PUBLISH_JOB_ID" | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"] == "succeeded"'
for node in "$PRIMARY" "${SECONDARIES[@]}"; do
  for trigger in "$TEST_DOMAIN" "*.$TEST_DOMAIN"; do
    for _ in $(seq 1 90); do
      if [[ "$(dig +short +time=2 +tries=1 @"$node" -p "$DNS_PORT" "$trigger.$ZONE" CNAME 2>/dev/null)" == "rpz-passthru." ]]; then
        break
      fi
      sleep 1
    done
    [[ "$(dig +short +time=2 +tries=1 @"$node" -p "$DNS_PORT" "$trigger.$ZONE" CNAME 2>/dev/null)" == "rpz-passthru." ]]
  done
done
curl -fsS "$API_URL/api/dns/overview" | python3 -c 'import json,sys; assert json.load(sys.stdin)["pendingPublish"] is False'
pass "RPZ exact and wildcard publish plus Primary/Secondary sync"

curl -fsS -X DELETE "$API_URL/api/dns/rpz/$RULE_ID" >/dev/null
curl -fsS "$API_URL/api/dns/overview" | python3 -c 'import json,sys; assert json.load(sys.stdin)["pendingPublish"] is True'
pass "deletion reopens pending publish"

PUBLISH_JOB_ID=$(curl -fsS -X POST "$API_URL/api/dns/rpz/publish" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
wait_publish_job
RULE_ID=""
printf 'PASS: deletion publish completed\n'

for suffix in one two three; do
  bulk_response=$(curl -fsS -H 'Content-Type: application/json' -d "{\"domain\":\"bulk-$suffix-$(date +%s%N).example.com\",\"reason\":\"bulk test\"}" "$API_URL/api/dns/rpz")
  BULK_IDS+=("$(printf '%s' "$bulk_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')")
done
bulk_json=$(printf '%s\n' "${BULK_IDS[@]}" | python3 -c 'import json,sys; print(json.dumps([line.strip() for line in sys.stdin if line.strip()]))')
deleted=$(curl -fsS -H 'Content-Type: application/json' -d "{\"ids\":$bulk_json}" "$API_URL/api/dns/rpz/bulk" | python3 -c 'import json,sys; print(json.load(sys.stdin)["deleted"])')
[[ "$deleted" == "3" ]]
BULK_IDS=()
PUBLISH_JOB_ID=$(curl -fsS -X POST "$API_URL/api/dns/rpz/publish" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
wait_publish_job
pass "RPZ bulk delete and publish task"

printf 'Functional tests passed: %d\n' "$((PASSED + 1))"
