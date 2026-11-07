#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for config in \
  tests/bind-cluster/config/primary/named.conf \
  tests/bind-cluster/config/secondary/named.conf \
  tests/bind-cluster/config/secondary-2/named.conf \
  tests/docker-production-bind/config/primary/named.conf \
  tests/docker-production-bind/config/secondary/named.conf \
  tests/docker-production-bind/config/secondary-2/named.conf; do
  if grep -Eq 'allow-(recursion|query-cache)[[:space:]]*\{[[:space:]]*any[[:space:]]*;' "$config"; then
    printf 'FAIL: open recursive/cache ACL in %s\n' "$config"
    exit 1
  fi
done

for compose_file in tests/bind-cluster/compose.yaml tests/docker-production-bind/compose.yaml; do
  docker compose -f "$compose_file" config --format json |
    python3 -c '
import json
import sys

config = json.load(sys.stdin)
for service_name, service in config.get("services", {}).items():
    for port in service.get("ports", []):
        host_ip = port.get("host_ip")
        if host_ip not in {"127.0.0.1", "::1"}:
            raise SystemExit(f"FAIL: non-loopback BIND test port {service_name}: {host_ip}")
print("PASS: BIND test Compose ports are loopback-only")
'
done

# This is a configuration gate, not a substitute for the real isolated E2E
# reachability check in tests/e2e/run-all.sh.
DNSGUARD_ENV_FILE=./deploy/docker/dnsguard.env.example \
  docker compose --env-file deploy/docker/dnsguard.env.example -f compose.yaml config --format json |
  python3 -c '
import json
import sys

config = json.load(sys.stdin)
services = config.get("services", {})
web = services.get("dnsguard-web", {})
api = services.get("dnsguard-api", {})
ports = web.get("ports", [])
if not ports:
    raise SystemExit("FAIL: Web has no explicit loopback port mapping")
for port in ports:
    host_ip = port.get("host_ip")
    if host_ip not in {"127.0.0.1", "::1"}:
        raise SystemExit(f"FAIL: Web port is not loopback-bound: {host_ip}")
if not any(str(port.get("published")) == "443" and str(port.get("target")) == "8443" for port in ports):
    raise SystemExit("FAIL: expected 127.0.0.1:443 -> 8443 Web mapping is missing")
if api.get("ports"):
    raise SystemExit("FAIL: API publishes a host port")
print("PASS: Web is loopback-bound and API has no host port")
'
