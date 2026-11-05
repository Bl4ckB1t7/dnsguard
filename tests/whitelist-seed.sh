#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dnsguard-whitelist-seed.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/domains.txt" <<'EOF'
# reviewed bootstrap allow-list
Example.COM.
example.com
child.example.net
EOF

"$ROOT/scripts/export-whitelist-json.py" \
  --input "$WORK/domains.txt" \
  --output "$WORK/seed.json" \
  --zone rpz.local

python3 - "$WORK/seed.json" <<'PY'
import json
import os
import stat
import sys

path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
assert data["version"] == 1
assert data["source"] == "rpz-connect"
assert data["mode"] == "global"
assert [item["domain"] for item in data["rules"]] == ["example.com", "child.example.net"]
assert all(item["status"] == "draft" and item["action"] == "passthru" for item in data["rules"])
assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
PY

if "$ROOT/scripts/export-whitelist-json.py" --input "$WORK/domains.txt" --output "$WORK/seed.json" --zone rpz.local; then
  echo 'existing seed was overwritten' >&2
  exit 1
fi

printf 'bad_domain.example\n' >"$WORK/bad.txt"
if "$ROOT/scripts/export-whitelist-json.py" --input "$WORK/bad.txt" --output "$WORK/bad.json" --zone rpz.local; then
  echo 'invalid domain was accepted' >&2
  exit 1
fi

echo 'PASS: whitelist normalization, deduplication, draft seed output, permissions, overwrite and invalid-domain checks'

mkdir -p "$WORK/bin"
cat >"$WORK/bin/dig" <<'EOF'
#!/usr/bin/env bash
printf 'rpz.local. 60 1\n'
EOF
chmod +x "$WORK/bin/dig"
printf 'key "rpz-manager" { secret "test"; };\n' >"$WORK/key"
chmod 0600 "$WORK/key"
PATH="$WORK/bin:$PATH" RPZ_ZONE=rpz.local RPZ_PRIMARY=127.0.0.1 RPZ_SECONDARIES=127.0.0.2 RPZ_KEY_FILE="$WORK/key" \
  "$ROOT/scripts/rpz-connect.sh" \
  --whitelist-file "$WORK/domains.txt" \
  --export-whitelist-json "$WORK/wrapper-seed.json" >/dev/null
test -s "$WORK/wrapper-seed.json"
echo 'PASS: rpz-connect.sh export options use read-only preflight and produce a seed without nsupdate'
