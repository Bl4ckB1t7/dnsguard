#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$ROOT/dns-lab"
SYSTEM_CONF="/etc/bind/dns-ops-lab"
SYSTEM_DATA="/var/lib/bind/dns-ops-lab"
SYSTEM_LOG="/var/log/named/dns-ops-lab"
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this lab script as root so named can drop to the kali user." >&2
  exit 1
fi
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.4/8 dev lo 2>/dev/null || true
mkdir -p "$LAB/run" "$LAB/logs" "$SYSTEM_CONF" "$SYSTEM_DATA/primary" "$SYSTEM_DATA/secondary" "$SYSTEM_DATA/secondary-2" "$SYSTEM_LOG"
install -o kali -g kali -m 640 "$LAB/keys/rpz-manager.key" "$SYSTEM_CONF/rpz-manager.key"
install -o kali -g kali -m 640 "$LAB/primary/named.conf" "$SYSTEM_CONF/primary.conf"
install -o kali -g kali -m 640 "$LAB/secondary/named.conf" "$SYSTEM_CONF/secondary.conf"
install -o kali -g kali -m 640 "$LAB/secondary-2/named.conf" "$SYSTEM_CONF/secondary-2.conf"
install -o kali -g kali -m 640 "$LAB/primary/rpz.local.zone" "$SYSTEM_DATA/primary/rpz.local.zone"
chown -R kali:kali "$SYSTEM_DATA" "$SYSTEM_LOG"

if [[ -f "$LAB/run/primary.pid" ]] && kill -0 "$(cat "$LAB/run/primary.pid")" 2>/dev/null; then
  echo "Primary already running: $(cat "$LAB/run/primary.pid")"
else
  named-checkconf "$SYSTEM_CONF/primary.conf"
  named -u kali -c "$SYSTEM_CONF/primary.conf" >"$LAB/logs/primary-stdout.log" 2>&1 &
  for _ in {1..20}; do [[ -s "$SYSTEM_DATA/primary/named.pid" ]] && break; sleep 0.1; done
  [[ -s "$SYSTEM_DATA/primary/named.pid" ]] || { echo "Primary failed to start" >&2; exit 1; }
  cat "$SYSTEM_DATA/primary/named.pid" >"$LAB/run/primary.pid"
fi

if [[ -f "$LAB/run/secondary.pid" ]] && kill -0 "$(cat "$LAB/run/secondary.pid")" 2>/dev/null; then
  echo "Secondary already running: $(cat "$LAB/run/secondary.pid")"
else
  named-checkconf "$SYSTEM_CONF/secondary.conf"
  named -u kali -c "$SYSTEM_CONF/secondary.conf" >"$LAB/logs/secondary-stdout.log" 2>&1 &
  for _ in {1..20}; do [[ -s "$SYSTEM_DATA/secondary/named.pid" ]] && break; sleep 0.1; done
  [[ -s "$SYSTEM_DATA/secondary/named.pid" ]] || { echo "Secondary failed to start" >&2; exit 1; }
  cat "$SYSTEM_DATA/secondary/named.pid" >"$LAB/run/secondary.pid"
fi

if [[ -f "$LAB/run/secondary-2.pid" ]] && kill -0 "$(cat "$LAB/run/secondary-2.pid")" 2>/dev/null; then
  echo "Secondary-2 already running: $(cat "$LAB/run/secondary-2.pid")"
else
  named-checkconf "$SYSTEM_CONF/secondary-2.conf"
  named -u kali -c "$SYSTEM_CONF/secondary-2.conf" >"$LAB/logs/secondary-2-stdout.log" 2>&1 &
  for _ in {1..20}; do [[ -s "$SYSTEM_DATA/secondary-2/named.pid" ]] && break; sleep 0.1; done
  [[ -s "$SYSTEM_DATA/secondary-2/named.pid" ]] || { echo "Secondary-2 failed to start" >&2; exit 1; }
  cat "$SYSTEM_DATA/secondary-2/named.pid" >"$LAB/run/secondary-2.pid"
fi

echo "BIND lab started: 127.0.0.2:5353 -> 127.0.0.3:5353, 127.0.0.4:5353"
