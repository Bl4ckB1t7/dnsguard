#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="${DNSGUARD_INSTALL_DIR:-/opt/dnsguard}"
CONFIG_DIR="${DNSGUARD_CONFIG_DIR:-/etc/dnsguard}"
DATA_DIR="${DNSGUARD_DATA_DIR:-/var/lib/dnsguard}"
LOG_DIR="${DNSGUARD_LOG_DIR:-/var/log/dnsguard}"
SYSTEM_USER="${DNSGUARD_USER:-dnsguard}"
SYSTEM_GROUP="${DNSGUARD_GROUP:-dnsguard}"
DRY_RUN=false
SKIP_SYSTEMD="${DNSGUARD_SKIP_SYSTEMD:-false}"
SYSTEMD_DIR="${DNSGUARD_SYSTEMD_DIR:-/etc/systemd/system}"

usage() {
  cat <<'HELP'
Usage: sudo ./scripts/install-dnsguard.sh [--dry-run]

Installs DNSGuard into /opt/dnsguard, creates its service account and runtime
folders, builds the frontend/API, and installs systemd unit files.
Override paths with DNSGUARD_INSTALL_DIR, DNSGUARD_CONFIG_DIR,
DNSGUARD_DATA_DIR, DNSGUARD_LOG_DIR, DNSGUARD_USER and DNSGUARD_GROUP.
HELP
}

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
elif [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
elif [[ $# -gt 0 ]]; then
  usage >&2
  exit 2
fi

if [[ "$DRY_RUN" == true ]]; then
  printf 'ROOT=%s\nINSTALL_DIR=%s\nCONFIG_DIR=%s\nDATA_DIR=%s\nLOG_DIR=%s\nUSER=%s\nGROUP=%s\n' \
    "$ROOT" "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$SYSTEM_USER" "$SYSTEM_GROUP"
  exit 0
fi

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0" >&2; exit 1; }
for command_name in go npm install systemctl useradd groupadd runuser tar; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "Missing required command: $command_name" >&2; exit 2; }
done

if ! getent group "$SYSTEM_GROUP" >/dev/null; then
  groupadd --system "$SYSTEM_GROUP"
fi
if ! id "$SYSTEM_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin --gid "$SYSTEM_GROUP" "$SYSTEM_USER"
fi

install -d -o "$SYSTEM_USER" -g "$SYSTEM_GROUP" -m 0750 "$INSTALL_DIR" "$DATA_DIR" "$DATA_DIR/rpz" "$LOG_DIR"
install -d -o root -g "$SYSTEM_GROUP" -m 0750 "$CONFIG_DIR"

if [[ "$ROOT" != "$INSTALL_DIR" ]]; then
  tar --exclude=.git --exclude=node_modules --exclude=dist --exclude=.run --exclude=data --exclude=dev \
    -C "$ROOT" -cf - . | tar -C "$INSTALL_DIR" -xf -
fi
chown -R "$SYSTEM_USER:$SYSTEM_GROUP" "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"

if [[ ! -f "$CONFIG_DIR/dnsguard.env" ]]; then
  install -o root -g "$SYSTEM_GROUP" -m 0640 "$INSTALL_DIR/.env.example" "$CONFIG_DIR/dnsguard.env"
fi

install -d -o "$SYSTEM_USER" -g "$SYSTEM_GROUP" -m 0700 "$INSTALL_DIR/.home" "$INSTALL_DIR/.run"
runuser -u "$SYSTEM_USER" -- env HOME="$INSTALL_DIR/.home" npm ci --ignore-scripts --prefix "$INSTALL_DIR"
runuser -u "$SYSTEM_USER" -- env HOME="$INSTALL_DIR/.home" npm run build --prefix "$INSTALL_DIR"
runuser -u "$SYSTEM_USER" -- env HOME="$INSTALL_DIR/.home" sh -c "cd '$INSTALL_DIR/server' && go build -o '$INSTALL_DIR/.run/dnsguard-api' ."

render_unit() {
  local source=$1 target=$2
  sed -e "s#^User=.*#User=$SYSTEM_USER#" \
      -e "s#^Group=.*#Group=$SYSTEM_GROUP#" \
      -e "s#^WorkingDirectory=.*#WorkingDirectory=$INSTALL_DIR#" \
      -e "s#^ExecStart=/opt/dnsguard#ExecStart=$INSTALL_DIR#" \
      -e "s#/etc/dnsguard#$CONFIG_DIR#g" \
      -e "s#/var/lib/dnsguard#$DATA_DIR#g" \
      -e "s#/var/log/dnsguard#$LOG_DIR#g" \
      "$source" > "$target"
}

tmp_api=$(mktemp)
tmp_monitor=$(mktemp)
trap 'rm -f "$tmp_api" "$tmp_monitor"' EXIT
render_unit "$ROOT/deploy/systemd/dnsguard-api.service" "$tmp_api"
render_unit "$ROOT/deploy/systemd/dnsguard-monitor.service" "$tmp_monitor"
if [[ "$SKIP_SYSTEMD" == true ]]; then
  echo "Skipping systemd installation because DNSGUARD_SKIP_SYSTEMD=true"
else
  install -d -o root -g root -m 0755 "$SYSTEMD_DIR"
  install -o root -g root -m 0644 "$tmp_api" "$SYSTEMD_DIR/dnsguard-api.service"
  install -o root -g root -m 0644 "$tmp_monitor" "$SYSTEMD_DIR/dnsguard-monitor.service"
  install -o root -g root -m 0644 "$ROOT/deploy/systemd/dnsguard-monitor.timer" "$SYSTEMD_DIR/dnsguard-monitor.timer"
  if [[ "$SYSTEMD_DIR" != "/etc/systemd/system" ]]; then
    echo "Systemd units rendered to $SYSTEMD_DIR; not enabled because a custom directory is in use."
  elif [[ "$(ps -p 1 -o comm=)" == systemd ]]; then
    systemctl daemon-reload
    systemctl enable dnsguard-api.service dnsguard-monitor.timer
  else
    echo "Warning: PID 1 is not systemd; unit files were installed but not enabled." >&2
  fi
fi

echo "DNSGuard installed. Next step: sudo $INSTALL_DIR/scripts/setup-dnsguard.sh"
