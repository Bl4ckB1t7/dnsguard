#!/usr/bin/env bash

# Shared host-path resolution for Docker Compose scripts. Relative paths are
# always relative to the repository root, never to the caller's current dir or
# to deploy/docker/.

dnsguard_resolve_path() {
  local raw="${1:-}" base="${2:-${ROOT:-$(pwd)}}" candidate
  [[ -n "$raw" ]] || { echo "empty path" >&2; return 1; }
  if [[ "$raw" == /* ]]; then
    candidate="$raw"
  else
    candidate="$base/$raw"
  fi
  realpath -m -- "$candidate"
}

dnsguard_validate_tsig_key_file() {
  local path="${1:-}" label="${2:-TSIG Key}" mode numeric
  [[ -n "$path" ]] || { echo "$label 路径为空" >&2; return 1; }
  [[ ! -L "$path" ]] || { echo "$label 不能是符号链接：$path" >&2; return 1; }
  [[ -f "$path" ]] || { echo "$label 必须是普通文件：$path" >&2; return 1; }
  [[ -r "$path" ]] || { echo "$label 当前用户不可读：$path" >&2; return 1; }
  mode="$(stat -c '%a' "$path" 2>/dev/null || true)"
  [[ "$mode" =~ ^[0-7][0-7][0-7][0-7]?$ ]] || { echo "$label 权限无法读取：$path" >&2; return 1; }
  numeric=$((8#$mode))
  if ((numeric & 7)); then
    echo "$label 对 other 开放了权限（当前 $mode），请先执行 chmod 0640 '$path'" >&2
    return 1
  fi
  if ! grep -Eq 'key[[:space:]]+"[^"]+"[[:space:]]*\{' "$path"; then
    echo "$label 格式无效：应包含 BIND key 配置块（不会输出密钥内容）" >&2
    return 1
  fi
  if ! grep -Eiq 'algorithm[[:space:]]+[A-Za-z0-9._-]+[[:space:]]*;' "$path"; then
    echo "$label 缺少 algorithm 配置" >&2
    return 1
  fi
  if ! grep -Eq 'secret[[:space:]]+"[^"]+"[[:space:]]*;' "$path"; then
    echo "$label 缺少非空 secret 配置" >&2
    return 1
  fi
}

dnsguard_validate_host_path() {
  local path="$1" label="$2" current
  case "$path" in
    /|/etc|/usr|/bin|/sbin|/var|/home|/root|"$ROOT"|"$ROOT/.git"|"$ROOT/.git/"*)
      echo "$label points to a dangerous or reserved path: $path" >&2
      return 1
      ;;
  esac
  # Do not follow a pre-existing symlink at any component of a configured
  # directory. This prevents a later mkdir/chown from escaping the target.
  current=""
  IFS='/' read -r -a _parts <<<"${path#/}"
  for _part in "${_parts[@]}"; do
    [[ -n "$_part" ]] || continue
    current="$current/$_part"
    if [[ -L "$current" ]]; then
      echo "$label contains a symlinked path component: $current" >&2
      return 1
    fi
  done
}

dnsguard_prepare_paths() {
  local root="$1" raw_data raw_secret raw_tls raw_logs
  ROOT="$root"
  raw_data="${DNSGUARD_DATA_DIR:-$ROOT/docker-data}"
  raw_secret="${DNSGUARD_SECRET_DIR:-$ROOT/secrets}"
  raw_tls="${DNSGUARD_TLS_DIR:-$ROOT/tls}"
  raw_logs="${DNSGUARD_BIND_LOG_DIR:-$ROOT/bind-logs}"
  [[ "$raw_data" == /* ]] || raw_data="$ROOT/$raw_data"
  [[ "$raw_secret" == /* ]] || raw_secret="$ROOT/$raw_secret"
  [[ "$raw_tls" == /* ]] || raw_tls="$ROOT/$raw_tls"
  [[ "$raw_logs" == /* ]] || raw_logs="$ROOT/$raw_logs"
  dnsguard_validate_host_path "$raw_data" DNSGUARD_DATA_DIR || return 1
  dnsguard_validate_host_path "$raw_secret" DNSGUARD_SECRET_DIR || return 1
  dnsguard_validate_host_path "$raw_tls" DNSGUARD_TLS_DIR || return 1
  dnsguard_validate_host_path "$raw_logs" DNSGUARD_BIND_LOG_DIR || return 1
  DNSGUARD_ENV_FILE="$(dnsguard_resolve_path "${DNSGUARD_ENV_FILE:-$ROOT/deploy/docker/dnsguard.env}" "$ROOT")"
  DNSGUARD_DATA_DIR="$(dnsguard_resolve_path "$raw_data" "$ROOT")"
  DNSGUARD_SECRET_DIR="$(dnsguard_resolve_path "$raw_secret" "$ROOT")"
  DNSGUARD_TLS_DIR="$(dnsguard_resolve_path "$raw_tls" "$ROOT")"
  DNSGUARD_BIND_LOG_DIR="$(dnsguard_resolve_path "$raw_logs" "$ROOT")"
  dnsguard_validate_host_path "$DNSGUARD_DATA_DIR" DNSGUARD_DATA_DIR || return 1
  dnsguard_validate_host_path "$DNSGUARD_SECRET_DIR" DNSGUARD_SECRET_DIR || return 1
  dnsguard_validate_host_path "$DNSGUARD_TLS_DIR" DNSGUARD_TLS_DIR || return 1
  dnsguard_validate_host_path "$DNSGUARD_BIND_LOG_DIR" DNSGUARD_BIND_LOG_DIR || return 1
  local left right
  for left in "$DNSGUARD_DATA_DIR" "$DNSGUARD_SECRET_DIR" "$DNSGUARD_TLS_DIR" "$DNSGUARD_BIND_LOG_DIR"; do
    for right in "$DNSGUARD_DATA_DIR" "$DNSGUARD_SECRET_DIR" "$DNSGUARD_TLS_DIR" "$DNSGUARD_BIND_LOG_DIR"; do
      [[ "$left" == "$right" ]] && continue
      case "$right/" in "$left/"*) echo "configured Docker directories overlap: $left and $right" >&2; return 1;; esac
    done
  done
  export DNSGUARD_ENV_FILE DNSGUARD_DATA_DIR DNSGUARD_SECRET_DIR DNSGUARD_TLS_DIR DNSGUARD_BIND_LOG_DIR
}
