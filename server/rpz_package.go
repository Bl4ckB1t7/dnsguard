package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// rpzPackageRequest deliberately contains configuration metadata only. It
// never accepts or returns TSIG secret material.
type rpzPackageRequest struct {
	Zone        string      `json:"zone"`
	GlobalDeny  string      `json:"globalDenyZone"`
	Primary     setupNode   `json:"primary"`
	Secondaries []setupNode `json:"secondaries"`
	TSIGKeyPath string      `json:"tsigKeyPath"`
	TSIGKeyMode string      `json:"tsigKeyMode"` // existing or admin-generate
}

type rpzPackageFile struct {
	Path       string `json:"path"`
	Content    string `json:"content"`
	Executable bool   `json:"executable,omitempty"`
}

type rpzPackagePreview struct {
	FormatVersion int              `json:"formatVersion"`
	Zone          string           `json:"zone"`
	GlobalDeny    string           `json:"globalDenyZone"`
	TSIGKeyMode   string           `json:"tsigKeyMode"`
	TSIGKeyName   string           `json:"tsigKeyName"`
	Files         []rpzPackageFile `json:"files"`
	Warnings      []string         `json:"warnings"`
}

var packageFileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var bindHostLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func normalizeRPZPackageRequest(request rpzPackageRequest) (rpzPackageRequest, error) {
	zone, err := normalizeSetupZone(request.Zone)
	if err != nil {
		return request, err
	}
	globalDeny := strings.TrimSpace(request.GlobalDeny)
	if globalDeny == "" {
		globalDeny = "global-deny.rpz.local"
	}
	globalDeny, err = normalizeSetupZone(globalDeny)
	if err != nil {
		return request, fmt.Errorf("Global Deny Zone 格式无效")
	}
	if strings.EqualFold(strings.TrimSuffix(zone, "."), strings.TrimSuffix(globalDeny, ".")) {
		return request, fmt.Errorf("业务 RPZ Zone 与 Global Deny Zone 不能相同")
	}

	mode := strings.ToLower(strings.TrimSpace(request.TSIGKeyMode))
	if mode == "" {
		mode = "existing"
	}
	if mode != "existing" && mode != "admin-generate" {
		return request, fmt.Errorf("TSIG Key 来源无效")
	}
	keyName := "rpz-manager.key"
	if strings.TrimSpace(request.TSIGKeyPath) != "" {
		clean := filepath.Clean(strings.TrimSpace(request.TSIGKeyPath))
		if clean != strings.TrimSpace(request.TSIGKeyPath) || filepath.Base(clean) != clean || !packageFileNamePattern.MatchString(clean) {
			return request, fmt.Errorf("TSIG Key 文件名无效；只能使用不含路径分隔符的安全文件名")
		}
		keyName = clean
	}

	primary, err := normalizePackageNode(request.Primary, "primary", "BIND-PRIMARY")
	if err != nil {
		return request, fmt.Errorf("Primary: %w", err)
	}
	if len(request.Secondaries) < 1 {
		return request, fmt.Errorf("至少需要一个 Secondary")
	}
	secondaries := make([]setupNode, 0, len(request.Secondaries))
	seen := map[string]bool{strings.ToLower(primary.Address): true}
	for index, secondary := range request.Secondaries {
		normalized, nodeErr := normalizePackageNode(secondary, "secondary", fmt.Sprintf("BIND-SECONDARY-%d", index+1))
		if nodeErr != nil {
			return request, fmt.Errorf("Secondary %d: %w", index+1, nodeErr)
		}
		key := strings.ToLower(normalized.Address)
		if seen[key] {
			return request, fmt.Errorf("DNS 节点地址重复: %s", normalized.Address)
		}
		seen[key] = true
		secondaries = append(secondaries, normalized)
	}

	request.Zone = zone
	request.GlobalDeny = globalDeny
	request.Primary = primary
	request.Secondaries = secondaries
	request.TSIGKeyMode = mode
	request.TSIGKeyPath = keyName
	return request, nil
}

func normalizePackageNode(node setupNode, role, fallbackName string) (setupNode, error) {
	address := strings.TrimSpace(node.Address)
	if !dnsNodeAddressAllowed(address) {
		return node, fmt.Errorf("地址无效或不在允许范围内")
	}
	host, port := packageNodeHostPort(address)
	if host == "" {
		return node, fmt.Errorf("地址缺少主机部分")
	}
	if !safeBINDHost(host) {
		return node, fmt.Errorf("地址包含不安全的主机名")
	}
	if port < 1 || port > 65535 {
		return node, fmt.Errorf("端口无效")
	}
	if node.Role != "" {
		kind, ok := dnsNodeRoleKind(node.Role)
		if !ok || kind != role {
			return node, fmt.Errorf("角色必须为 %s", role)
		}
	}
	name := strings.TrimSpace(node.Name)
	if name == "" {
		name = fallbackName
	}
	if !packageFileNamePattern.MatchString(name) {
		return node, fmt.Errorf("节点名称包含不安全字符")
	}
	node.Name = name
	node.Role = role
	node.Address = address
	return node, nil
}

func safeBINDHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 || strings.Contains(host, "..") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !bindHostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func packageNodeHostPort(address string) (string, int) {
	if host, portText, err := net.SplitHostPort(address); err == nil {
		port, _ := strconv.Atoi(portText)
		return strings.Trim(host, "[]"), port
	}
	host, portText := splitDNSAddress(address)
	port := 53
	if parsed, err := strconv.Atoi(portText); err == nil {
		port = parsed
	}
	return strings.Trim(host, "[]"), port
}

func packageNodeHost(address string) string {
	host, _ := packageNodeHostPort(address)
	return host
}

func rpzPackageFiles(request rpzPackageRequest) rpzPackagePreview {
	zone := strings.TrimSuffix(request.Zone, ".")
	globalDeny := strings.TrimSuffix(request.GlobalDeny, ".")
	primaryHost := packageNodeHost(request.Primary.Address)
	secondaryHosts := make([]string, 0, len(request.Secondaries))
	for _, node := range request.Secondaries {
		secondaryHosts = append(secondaryHosts, packageNodeHost(node.Address))
	}
	keyPath := "/etc/bind/keys/" + request.TSIGKeyPath
	primaryDataDir := "/var/lib/bind/dnsguard-rpz-primary"
	secondaryDataDir := "/var/cache/bind/dnsguard-rpz-secondary"
	files := []rpzPackageFile{
		{Path: "README.md", Content: renderPackageReadme(request, keyPath)},
		{Path: "config/tsig.conf", Content: fmt.Sprintf("// Include the protected key on the BIND host. DNSGuard never receives the secret in this package.\ninclude %q;\n", keyPath)},
		{Path: "config/rpz-primary.conf", Content: renderPrimaryConfig(zone, globalDeny, primaryHost, secondaryHosts, primaryDataDir)},
		{Path: "config/rpz-secondary.conf", Content: renderSecondaryConfig(zone, globalDeny, primaryHost, secondaryDataDir)},
		{Path: "config/response-policy.conf", Content: renderResponsePolicyConfig(zone, globalDeny)},
		{Path: "zones/db." + zone, Content: renderRPZZone(zone)},
		{Path: "zones/db." + globalDeny, Content: renderGlobalDenyZone(globalDeny)},
		{Path: "verify-rpz-config.sh", Content: renderVerifyScript(zone, globalDeny), Executable: true},
		{Path: "apply-rpz-config.sh", Content: renderApplyScript(zone, globalDeny), Executable: true},
	}
	manifest, _ := json.MarshalIndent(map[string]any{
		"formatVersion":  1,
		"zone":           request.Zone,
		"globalDenyZone": request.GlobalDeny,
		"primary":        request.Primary.Address,
		"secondaries":    secondaryHosts,
		"tsigKeyMode":    request.TSIGKeyMode,
		"tsigKeyName":    request.TSIGKeyPath,
	}, "", "  ")
	files = append(files, rpzPackageFile{Path: "manifest.json", Content: string(manifest) + "\n"})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	warnings := []string{
		"本包不包含 TSIG Secret；existing 模式需要管理员复制已有授权 Key，admin-generate 模式需要在 BIND 受保护环境运行 tsig-keygen。",
		"应用前必须由 BIND 管理员审核、备份并执行 named-checkconf/named-checkzone。DNSGuard 不会远程写入或重载 BIND。",
		"Global Deny Zone 可以预创建，但在白名单发布并确认所有 Secondary 同步前，不得加入 response-policy。",
	}
	return rpzPackagePreview{FormatVersion: 1, Zone: request.Zone, GlobalDeny: request.GlobalDeny, TSIGKeyMode: request.TSIGKeyMode, TSIGKeyName: request.TSIGKeyPath, Files: files, Warnings: warnings}
}

func renderPackageReadme(request rpzPackageRequest, keyPath string) string {
	keyInstructions := fmt.Sprintf("复制现有、已授权的 TSIG Key 到 BIND 主机的 `%s`，并确认 Primary 的 update-policy 与 Key 名称一致。不要把 Key 内容放入本包。", keyPath)
	if request.TSIGKeyMode == "admin-generate" {
		keyInstructions = fmt.Sprintf("在 BIND 主机受保护环境执行 `install -d -m 0750 /etc/bind/keys && tsig-keygen -a hmac-sha256 rpz-manager > %s && chmod 0640 %s`，再把同一份 Key 安全提供给 DNSGuard。重新生成后必须同步更新 Primary 配置。", keyPath, keyPath)
	}
	return fmt.Sprintf(`# DNSGuard RPZ 初始化配置包

本包由 DNSGuard 根据已审核的节点信息生成，业务 Zone 为 "%s"，Global Deny Zone 为 "%s"。
它不包含 TSIG Secret，不会通过 SSH、Docker Socket 或其他方式修改 BIND。

## 应用前检查

1. 由 BIND 管理员在对应 Primary/Secondary 主机审核所有片段和路径。
2. %s
3. 在 Primary 包目录先运行：

   BIND_CONFIG_ROOT=/etc/bind ./apply-rpz-config.sh --check primary

4. 确认不会覆盖已有 dnsguard-rpz 目录后，再由管理员明确执行：

   BIND_CONFIG_ROOT=/etc/bind ./apply-rpz-config.sh --apply primary

Secondary 主机使用同一个包但只应用对应片段：

   BIND_CONFIG_ROOT=/etc/bind ./apply-rpz-config.sh --check secondary
   BIND_CONFIG_ROOT=/etc/bind ./apply-rpz-config.sh --apply secondary

脚本只在 BIND 主机的 BIND_CONFIG_ROOT 下创建不存在的生成目录，并备份现有
named.conf/named.conf.local 到时间戳目录；发现冲突会停止，不会追加重复配置。
Primary 动态 Zone 和 journal 使用 /var/lib/bind/dnsguard-rpz-primary；Secondary 的
AXFR/IXFR 传区文件使用 /var/cache/bind/dnsguard-rpz-secondary。脚本只为这些目录设置
0750 和 BIND_USER:BIND_GROUP（默认 bind:bind），不会递归修改其中已有文件。

## 审核与验证

将 config/tsig.conf、config/rpz-primary.conf 和 config/rpz-secondary.conf 按
管理员的现有布局纳入配置；先 include config/tsig.conf，再 include 对应的
Primary/Secondary 片段，确保 rpz-manager Key 已定义。验证脚本需要 BIND_NAMED_CONF 指向实际已加载的
named.conf；未提供时只验证 Zone 文件，并明确显示最终配置检查未执行。确认
named-checkzone 和 named-checkconf 针对实际 named.conf 通过，再按现有变更流程
reload BIND。Primary 运行
./verify-rpz-config.sh primary；Secondary 在传区文件出现后运行
./verify-rpz-config.sh secondary。

config/response-policy.conf 只启用业务 RPZ；其中 Global Deny 行保持注释。只有白名单
发布成功、Primary 和全部 Secondary 完成同步后，管理员才可以将 Global Deny 加入
response-policy，随后返回 DNSGuard 执行只读 SOA、TSIG、NOTIFY/IXFR/AXFR 和递归检查。

如果应用或审核失败，保留时间戳备份，移除的只能是本包创建的 dnsguard-rpz 目录；不要
清空现有 BIND Zone、journal 或其他配置。恢复后按管理员的正常变更流程检查配置。
`, strings.TrimSuffix(request.Zone, "."), strings.TrimSuffix(request.GlobalDeny, "."), keyInstructions)
}

func renderPrimaryConfig(zone, globalDeny, primary string, secondaries []string, dataDir string) string {
	notifyEntries := make([]string, 0, len(secondaries))
	for _, secondary := range secondaries {
		notifyEntries = append(notifyEntries, secondary+" key rpz-manager")
	}
	notify := strings.Join(notifyEntries, ";\n        ")
	return fmt.Sprintf(`// Review and include this fragment from the Primary named.conf.
// It does not enable Global Deny in response-policy.
zone %q {
    type master;
    file %q;
    update-policy { grant rpz-manager zonesub ANY; };
    allow-transfer { key rpz-manager; };
    also-notify { %s; };
};

zone %q {
    type master;
    file %q;
    update-policy { grant rpz-manager zonesub ANY; };
    allow-transfer { key rpz-manager; };
    also-notify { %s; };
};
`, zone, dataDir+"/db."+zone, notify, globalDeny, dataDir+"/db."+globalDeny, notify)
}

func renderSecondaryConfig(zone, globalDeny, primary, dataDir string) string {
	return fmt.Sprintf(`// Include this fragment on each Secondary after reviewing the paths.
zone %q {
    type slave;
    masters { %s key rpz-manager; };
    file %q;
};

zone %q {
    type slave;
    masters { %s key rpz-manager; };
    file %q;
};
`, zone, primary, dataDir+"/db."+zone, globalDeny, primary, dataDir+"/db."+globalDeny)
}

func renderResponsePolicyConfig(zone, globalDeny string) string {
	return fmt.Sprintf(`// Keep the business RPZ first. Add the commented Global Deny line only
// after whitelist publication and Primary/Secondary verification.
response-policy {
    zone %q;
    // zone %q;
};
`, zone, globalDeny)
}

func renderRPZZone(zone string) string {
	return fmt.Sprintf(`$ORIGIN %s.
$TTL 60
@ IN SOA ns1.dnsguard.invalid. hostmaster.dnsguard.invalid. ( 1 60 60 60 60 )
@ IN NS ns1.dnsguard.invalid.
`, zone)
}

func renderGlobalDenyZone(zone string) string {
	return fmt.Sprintf(`$ORIGIN %s.
$TTL 60
@ IN SOA ns1.dnsguard.invalid. hostmaster.dnsguard.invalid. ( 1 60 60 60 60 )
@ IN NS ns1.dnsguard.invalid.
* IN CNAME .
`, zone)
}

func renderVerifyScript(zone, globalDeny string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
PACKAGE_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
ROLE=${1:-}
PRIMARY_DATA_DIR=${PRIMARY_DATA_DIR:-/var/lib/bind/dnsguard-rpz-primary}
SECONDARY_DATA_DIR=${SECONDARY_DATA_DIR:-/var/cache/bind/dnsguard-rpz-secondary}
if [[ "$ROLE" != primary && "$ROLE" != secondary ]]; then
  echo "usage: BIND_CONFIG_ROOT=/etc/bind BIND_NAMED_CONF=/etc/bind/named.conf $0 primary|secondary" >&2
  exit 2
fi
command -v named-checkzone >/dev/null || { echo "named-checkzone is required" >&2; exit 1; }
check_zone() {
  local zone="$1" actual="$2" package="$3"
  if [[ -f "$actual" ]]; then
    named-checkzone "$zone" "$actual"
    return
  fi
  [[ -f "$package" ]] || { echo "zone file is missing: $actual" >&2; exit 1; }
  named-checkzone "$zone" "$package"
  echo "NOT RUN: actual loaded zone file is not present yet: $actual" >&2
}
if [[ "$ROLE" == primary ]]; then
  check_zone %q "$PRIMARY_DATA_DIR/db.%s" "$PACKAGE_DIR/zones/db.%s"
  check_zone %q "$PRIMARY_DATA_DIR/db.%s" "$PACKAGE_DIR/zones/db.%s"
else
  check_zone %q "$SECONDARY_DATA_DIR/db.%s" "$PACKAGE_DIR/zones/db.%s"
  check_zone %q "$SECONDARY_DATA_DIR/db.%s" "$PACKAGE_DIR/zones/db.%s"
fi
if [[ -n ${BIND_NAMED_CONF:-} ]]; then
  [[ -f "$BIND_NAMED_CONF" ]] || { echo "BIND_NAMED_CONF does not exist: $BIND_NAMED_CONF" >&2; exit 1; }
  command -v named-checkconf >/dev/null || { echo "named-checkconf is required" >&2; exit 1; }
  named-checkconf -z "$BIND_NAMED_CONF"
else
  echo "NOT RUN: set BIND_NAMED_CONF to the final loaded named.conf for named-checkconf -z" >&2
fi
`, zone, zone, zone, globalDeny, globalDeny, globalDeny, zone, zone, zone, globalDeny, globalDeny, globalDeny)
}

func renderApplyScript(zone, globalDeny string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
ROOT=${BIND_CONFIG_ROOT:-/etc/bind}
PACKAGE_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
TARGET="$ROOT/dnsguard-rpz"
BACKUP="$ROOT/dnsguard-rpz-backups/$(date -u +%%Y%%m%%dT%%H%%M%%SZ)"
STAGE="$ROOT/.dnsguard-rpz-stage.$$"
ROLE=${2:-}
PRIMARY_DATA_DIR=${PRIMARY_DATA_DIR:-/var/lib/bind/dnsguard-rpz-primary}
SECONDARY_DATA_DIR=${SECONDARY_DATA_DIR:-/var/cache/bind/dnsguard-rpz-secondary}
BIND_USER=${BIND_USER:-bind}
BIND_GROUP=${BIND_GROUP:-bind}
BUSINESS_ZONE=%q
GLOBAL_DENY_ZONE=%q
cleanup() { rm -rf -- "$STAGE"; }
trap cleanup EXIT
if [[ ${1:-} != "--check" && ${1:-} != "--apply" ]] || [[ "$ROLE" != primary && "$ROLE" != secondary ]]; then
  echo "usage: BIND_CONFIG_ROOT=/etc/bind $0 --check|--apply primary|secondary" >&2
  exit 2
fi
[[ "$ROOT" = /* && "$ROOT" != "/" ]] || { echo "BIND_CONFIG_ROOT must be an absolute non-root path" >&2; exit 1; }
[[ -d "$ROOT" ]] || { echo "BIND_CONFIG_ROOT does not exist: $ROOT" >&2; exit 1; }
command -v install >/dev/null || { echo "install is required" >&2; exit 1; }
id "$BIND_USER" >/dev/null 2>&1 || { echo "BIND_USER does not exist: $BIND_USER" >&2; exit 1; }
getent group "$BIND_GROUP" >/dev/null 2>&1 || { echo "BIND_GROUP does not exist: $BIND_GROUP" >&2; exit 1; }
for required in config zones; do
  [[ -d "$PACKAGE_DIR/$required" ]] || { echo "package is incomplete: $required" >&2; exit 1; }
done
DATA_DIR="$PRIMARY_DATA_DIR"
[[ "$ROLE" == primary ]] || DATA_DIR="$SECONDARY_DATA_DIR"
prepare_data_dir() {
  if [[ -L "$DATA_DIR" ]]; then
    echo "refusing to use symlink as BIND data directory: $DATA_DIR" >&2
    return 1
  fi
  install -d -o "$BIND_USER" -g "$BIND_GROUP" -m 0750 -- "$DATA_DIR"
}
prepare_generated_files() {
  # The package is normally extracted by an administrator, so its files may
  # otherwise be unreadable by named.  Restrict ownership and permissions to
  # the generated package only; never recurse into an existing BIND tree.
  chown "$BIND_USER:$BIND_GROUP" "$TARGET" "$TARGET/config" "$TARGET/zones"
  chmod 0750 "$TARGET" "$TARGET/config" "$TARGET/zones"
  find "$TARGET/config" "$TARGET/zones" -type f -exec chown "$BIND_USER:$BIND_GROUP" {} + -exec chmod 0640 {} +
  chown "$BIND_USER:$BIND_GROUP" "$TARGET/manifest.json" "$TARGET/applied-role"
  chmod 0640 "$TARGET/manifest.json" "$TARGET/applied-role"
}
same_package() {
  [[ -d "$TARGET/config" && -d "$TARGET/zones" ]] || return 1
  [[ -f "$TARGET/manifest.json" && -f "$TARGET/applied-role" ]] || return 1
  [[ "$(cat -- "$TARGET/applied-role")" == "$ROLE" ]] || return 1
  diff -qr -- "$PACKAGE_DIR/config" "$TARGET/config" >/dev/null 2>&1 || return 1
  diff -qr -- "$PACKAGE_DIR/zones" "$TARGET/zones" >/dev/null 2>&1 || return 1
  cmp -s -- "$PACKAGE_DIR/manifest.json" "$TARGET/manifest.json"
}
copy_new_zone() {
  local source="$1" target="$2"
  if [[ -L "$target" ]]; then
    echo "refusing to write through symlink: $target" >&2
    return 1
  fi
  if [[ -e "$target" ]]; then
    cmp -s -- "$source" "$target" || { echo "refusing to overwrite existing zone file: $target" >&2; return 1; }
    return 0
  fi
  install -o "$BIND_USER" -g "$BIND_GROUP" -m 0640 -- "$source" "$target"
}
verify() { "$PACKAGE_DIR/verify-rpz-config.sh" "$ROLE"; }
if [[ -L "$TARGET" ]]; then
  echo "refusing to use symlink as generated configuration directory: $TARGET" >&2
  exit 1
fi
if [[ -e "$TARGET" ]]; then
  [[ -d "$TARGET" ]] || { echo "refusing to replace non-directory $TARGET" >&2; exit 1; }
  if same_package; then
    prepare_generated_files
    prepare_data_dir
    if [[ "$ROLE" == primary ]]; then
      copy_new_zone "$PACKAGE_DIR/zones/db.$BUSINESS_ZONE" "$DATA_DIR/db.$BUSINESS_ZONE"
      copy_new_zone "$PACKAGE_DIR/zones/db.$GLOBAL_DENY_ZONE" "$DATA_DIR/db.$GLOBAL_DENY_ZONE"
    fi
    verify
    echo "CHECK PASS: the same $ROLE package is already present at $TARGET"
    exit 0
  fi
  echo "refusing to overwrite existing $TARGET; back it up and review conflicts manually" >&2
  exit 1
fi
for candidate in "$ROOT/named.conf" "$ROOT/named.conf.local"; do
  [[ -f "$candidate" ]] || continue
  if grep -Eq "zone[[:space:]]+\"($BUSINESS_ZONE|$GLOBAL_DENY_ZONE)\"" "$candidate"; then
    echo "existing BIND zone declaration found in $candidate; refusing duplicate configuration" >&2
    exit 1
  fi
done
if [[ ${1:-} = "--check" ]]; then
  verify
  echo "CHECK PASS: no existing generated directory; named.conf was not modified"
  exit 0
fi
install -d -m 0750 -- "$BACKUP"
for candidate in "$ROOT/named.conf" "$ROOT/named.conf.local"; do
  [[ -f "$candidate" ]] && cp -p -- "$candidate" "$BACKUP/$(basename "$candidate")"
done
install -d -m 0750 -- "$STAGE/config" "$STAGE/zones"
cp -a -- "$PACKAGE_DIR/config" "$PACKAGE_DIR/zones" "$STAGE/"
cp -p -- "$PACKAGE_DIR/manifest.json" "$STAGE/manifest.json"
printf '%%s\n' "$ROLE" > "$STAGE/applied-role"
mv -- "$STAGE" "$TARGET"
prepare_generated_files
prepare_data_dir
if [[ "$ROLE" == primary ]]; then
  copy_new_zone "$PACKAGE_DIR/zones/db.$BUSINESS_ZONE" "$DATA_DIR/db.$BUSINESS_ZONE"
  copy_new_zone "$PACKAGE_DIR/zones/db.$GLOBAL_DENY_ZONE" "$DATA_DIR/db.$GLOBAL_DENY_ZONE"
fi
echo "APPLY PASS: generated $ROLE files copied to $TARGET"
echo "BIND data directory prepared with mode 0750 for $BIND_USER:$BIND_GROUP: $DATA_DIR"
echo "Manual next step: review and include the config fragments, then run named-checkconf and reload BIND through your normal change process."
echo "Global Deny remains absent from response-policy until whitelist synchronization is verified."
echo "Recovery: if review fails, remove only $TARGET and restore the timestamped files from $BACKUP; do not clear existing BIND data."
`, zone, globalDeny)
}

func buildRPZPackage(request rpzPackageRequest) (rpzPackagePreview, error) {
	normalized, err := normalizeRPZPackageRequest(request)
	if err != nil {
		return rpzPackagePreview{}, err
	}
	return rpzPackageFiles(normalized), nil
}

func setupRPZPackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !setupAdminAuthenticated(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "需要已登录管理员会话和 CSRF Token"})
		return
	}
	var request rpzPackageRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}
	preview, err := buildRPZPackage(request)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func downloadRPZPackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !setupAdminAuthenticated(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "需要已登录管理员会话和 CSRF Token"})
		return
	}
	var request rpzPackageRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}
	preview, err := buildRPZPackage(request)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, file := range preview.Files {
		header := &zip.FileHeader{Name: "dnsguard-rpz-package/" + file.Path, Method: zip.Deflate}
		if file.Executable {
			header.SetMode(0o750)
		} else {
			header.SetMode(0o640)
		}
		writer, createErr := archive.CreateHeader(header)
		if createErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "生成配置包失败"})
			return
		}
		if _, writeErr := writer.Write([]byte(file.Content)); writeErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "写入配置包失败"})
			return
		}
	}
	if err := archive.Close(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "关闭配置包失败"})
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="dnsguard-rpz-package.zip"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buffer.Bytes())
}
