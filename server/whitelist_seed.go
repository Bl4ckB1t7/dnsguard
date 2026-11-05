package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	whitelistSeedVersion  = 1
	whitelistSeedMaxSize  = 8 * 1024 * 1024
	whitelistSeedMaxRules = 100_000
)

func configuredPolicyMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("RPZ_DEFAULT_DENY_MODE")))
	if mode == "global" {
		return "global"
	}
	return "legacy"
}

func configuredPolicyModeError() error {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("RPZ_DEFAULT_DENY_MODE")))
	if mode == "" || mode == "legacy" || mode == "global" {
		return nil
	}
	return fmt.Errorf("RPZ_DEFAULT_DENY_MODE 无效: %q（只能是 global 或 legacy）", mode)
}

// effectivePolicyMode is deliberately based on persisted state after setup.
// An old state without PolicyMode is historical legacy data, not an implicit
// opt-in to global deny.
func effectivePolicyMode() string {
	dnsMu.RLock()
	persisted := strings.ToLower(strings.TrimSpace(state.PolicyMode))
	dnsMu.RUnlock()
	if persisted == "global" || persisted == "legacy" {
		return persisted
	}
	if isInitialized() {
		// A completed installation without the v1.1 field is historical legacy
		// data. Never let a new environment variable opt it into global deny.
		return "legacy"
	}
	return configuredPolicyMode()
}

func validatePolicyModeConsistency() error {
	if err := configuredPolicyModeError(); err != nil {
		return err
	}
	if !isInitialized() {
		return nil
	}
	dnsMu.RLock()
	persisted := strings.ToLower(strings.TrimSpace(state.PolicyMode))
	dnsMu.RUnlock()
	if persisted == "" {
		persisted = "legacy"
	}
	if persisted != "global" && persisted != "legacy" {
		return fmt.Errorf("DNS 状态中的 PolicyMode 无效: %q；为保护现有策略，已停止启动", persisted)
	}
	configured := configuredPolicyMode()
	if persisted != configured {
		return fmt.Errorf("策略模式不一致：持久化状态=%s，环境变量=%s；旧部署不会自动迁移，请完成受控迁移后再启动", persisted, configured)
	}
	return nil
}

func configuredGlobalDenyZone() string {
	return strings.TrimSuffix(strings.TrimSpace(os.Getenv("RPZ_GLOBAL_DENY_ZONE")), ".")
}

// globalDenySetupDeferred is an explicit first-install safety switch. It lets
// an administrator complete setup and publish the reviewed whitelist before
// adding the pre-created deny Zone to BIND response-policy.
func globalDenySetupDeferred() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("RPZ_GLOBAL_DENY_SETUP_DEFERRED")), "true")
}

type whitelistSeed struct {
	Version     int       `json:"version"`
	Source      string    `json:"source"`
	Mode        string    `json:"mode"`
	GeneratedAt string    `json:"generatedAt"`
	Zone        string    `json:"zone"`
	Rules       []RPZRule `json:"rules"`
}

type whitelistSeedStatus struct {
	Available bool   `json:"available"`
	Count     int    `json:"count,omitempty"`
	Source    string `json:"source,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Error     string `json:"error,omitempty"`
}

func whitelistSeedPath() string {
	return strings.TrimSpace(os.Getenv("RPZ_WHITELIST_SEED_FILE"))
}

func inspectWhitelistSeed() whitelistSeedStatus {
	path := whitelistSeedPath()
	if path == "" {
		if configuredPolicyMode() == "global" && !globalDenySetupDeferred() {
			return whitelistSeedStatus{Error: "全局默认拒绝模式尚未配置白名单初始 JSON"}
		}
		return whitelistSeedStatus{}
	}
	seed, err := readWhitelistSeed(path, "")
	if err != nil {
		return whitelistSeedStatus{Error: "白名单初始 JSON 不可用，请检查部署目录和格式"}
	}
	return whitelistSeedStatus{Available: true, Count: len(seed.Rules), Source: seed.Source, Mode: seed.Mode}
}

func readWhitelistSeed(path, expectedZone string) (whitelistSeed, error) {
	var seed whitelistSeed
	path = filepath.Clean(path)
	root := filepath.Clean(filepath.Dir(dnsStatePath()))
	if path == "." || !pathWithin(root, path) {
		return seed, fmt.Errorf("白名单初始 JSON 必须位于 DNSGuard 数据目录")
	}
	info, err := os.Lstat(path) // #nosec G703 -- deployment path is restricted to the DNSGuard data directory.
	if err != nil {
		return seed, fmt.Errorf("白名单初始 JSON 不存在: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return seed, fmt.Errorf("白名单初始 JSON 必须是普通文件")
	}
	if info.Mode().Perm()&0o007 != 0 {
		return seed, fmt.Errorf("白名单初始 JSON 不得对其他用户开放")
	}
	if info.Size() <= 0 || info.Size() > whitelistSeedMaxSize {
		return seed, fmt.Errorf("白名单初始 JSON 大小无效")
	}
	content, err := os.ReadFile(path) // #nosec G304 -- path was constrained above.
	if err != nil {
		return seed, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&seed); err != nil {
		return seed, fmt.Errorf("白名单初始 JSON 格式无效: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return seed, fmt.Errorf("白名单初始 JSON 包含多余内容")
	}
	if seed.Version != whitelistSeedVersion || seed.Source != "rpz-connect" || seed.Mode != "global" {
		return seed, fmt.Errorf("白名单初始 JSON 版本、来源或模式无效")
	}
	zone, err := normalizeSetupZone(seed.Zone)
	if err != nil {
		return seed, fmt.Errorf("白名单初始 JSON Zone 无效")
	}
	if expectedZone != "" {
		expected, expectedErr := normalizeSetupZone(expectedZone)
		if expectedErr != nil || !strings.EqualFold(zone, expected) {
			return seed, fmt.Errorf("白名单初始 JSON Zone 与初始化 Zone 不一致")
		}
	}
	if len(seed.Rules) == 0 || len(seed.Rules) > whitelistSeedMaxRules {
		return seed, fmt.Errorf("白名单初始 JSON 规则数量无效")
	}
	seen := make(map[string]struct{}, len(seed.Rules))
	now := time.Now().UTC().Format(time.RFC3339)
	for index := range seed.Rules {
		rule := &seed.Rules[index]
		rule.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.Domain), "."))
		if !domainPattern.MatchString(rule.Domain) {
			return seed, fmt.Errorf("白名单初始 JSON 第 %d 条域名无效", index+1)
		}
		if _, exists := seen[rule.Domain]; exists {
			return seed, fmt.Errorf("白名单初始 JSON 存在重复域名: %s", rule.Domain)
		}
		seen[rule.Domain] = struct{}{}
		if !strings.EqualFold(strings.TrimSpace(rule.Action), "passthru") || !strings.EqualFold(strings.TrimSpace(rule.Type), "CNAME") {
			return seed, fmt.Errorf("白名单初始 JSON 第 %d 条必须是 PASSTHRU CNAME", index+1)
		}
		rule.ID = nextRuleID()
		rule.Action = "passthru"
		rule.Type = "CNAME"
		rule.Value = "rpz-passthru."
		rule.Status = "draft"
		rule.UpdatedAt = now
		if strings.TrimSpace(rule.Reason) == "" {
			rule.Reason = "preflight whitelist import"
		}
	}
	seed.Zone = zone
	return seed, nil
}

func loadWhitelistSeedForZone(zone string) ([]RPZRule, error) {
	path := whitelistSeedPath()
	if path == "" {
		if configuredPolicyMode() == "global" && !globalDenySetupDeferred() {
			return nil, fmt.Errorf("全局默认拒绝模式必须配置白名单初始 JSON")
		}
		return nil, nil
	}
	seed, err := readWhitelistSeed(path, zone)
	if err != nil {
		return nil, err
	}
	return seed.Rules, nil
}
