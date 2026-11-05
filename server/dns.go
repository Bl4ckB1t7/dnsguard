package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type DNSNode struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Address     string `json:"address"`
	Status      string `json:"status"`
	RPZVersion  string `json:"rpzVersion"`
	LastSync    string `json:"lastSync"`
	LastChecked string `json:"lastChecked"`
}

type DNSNodeConfig struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Role    string `json:"role"`
	Address string `json:"address"`
}

type RPZRule struct {
	ID        string `json:"id"`
	Domain    string `json:"domain"`
	Action    string `json:"action"`
	Type      string `json:"type,omitempty"`
	Value     string `json:"value,omitempty"`
	Reason    string `json:"reason"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updatedAt"`
}

type RPZRecord struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Policy    string `json:"policy"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updatedAt"`
}

type dnsState struct {
	Nodes         []DNSNode    `json:"nodes"`
	Rules         []RPZRule    `json:"rules"`
	Published     []RPZRule    `json:"published"`
	Versions      []RPZVersion `json:"versions"`
	RulesRevision uint64       `json:"rulesRevision,omitempty"`
	PolicyMode    string       `json:"policyMode,omitempty"`
}

type RPZVersion struct {
	ID        string    `json:"id"`
	CreatedAt string    `json:"createdAt"`
	Mode      string    `json:"mode"`
	Rules     []RPZRule `json:"rules"`
}

type RPZChange struct {
	Type   string `json:"type"`
	Domain string `json:"domain"`
	Before string `json:"before"`
	After  string `json:"after"`
}

var dnsMu sync.RWMutex
var state = dnsState{}
var domainPattern = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$`)
var dnsHealthMu sync.Mutex
var dnsHealthCache []DNSNode
var dnsHealthAt time.Time
var dnsHealthRefreshing atomic.Bool
var ruleSequence atomic.Uint64
var nodeSequence atomic.Uint64
var stateFileMu sync.Mutex
var nodeConfigFileMu sync.Mutex

// dnsStateMutationMu keeps an in-memory mutation and its durable write as one
// serialized operation. Without it, a failed write could be restored over a
// concurrent successful mutation.
var dnsStateMutationMu sync.Mutex

func nextRuleID() string {
	return fmt.Sprintf("rule-%d-%d", time.Now().UTC().UnixNano(), ruleSequence.Add(1))
}

func nextNodeID() string {
	return fmt.Sprintf("node-%d-%d", time.Now().UTC().UnixNano(), nodeSequence.Add(1))
}

func rpzLogMaxBytes() int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("RPZ_LOG_MAX_BYTES")), 10, 64)
	if err != nil || value < 64*1024 || value > 100*1024*1024 {
		return 5 * 1024 * 1024
	}
	return value
}

func readRPZLogTail(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G703 -- RPZ_LOG_FILES is an administrator-controlled read-only log path.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		if _, err := file.Seek(-maxBytes, io.SeekEnd); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(file, maxBytes))
}

func rpzHitCount() (int, bool) {
	files := make([]string, 0)
	for _, item := range strings.Split(os.Getenv("RPZ_LOG_FILES"), ",") {
		if path := strings.TrimSpace(item); path != "" {
			files = append(files, path)
		}
	}
	if len(files) == 0 {
		return 0, false
	}
	rawCount := 0
	readable := false
	markers := []string{"rpz QNAME", "rpz CLIENT-IP", "rpz IP", "rpz NSDNAME", "rpz NSIP"}
	unique := make(map[string]struct{})
	window := 2
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RPZ_HIT_DEDUP_SECONDS"))); err == nil && configured > 0 {
		window = configured
	}
	for _, path := range files {
		content, err := readRPZLogTail(path, rpzLogMaxBytes())
		if err != nil {
			continue
		}
		readable = true
		for _, line := range strings.Split(string(content), "\n") {
			for _, marker := range markers {
				if strings.Contains(line, marker) {
					if key, ok := rpzHitFingerprint(line, window); ok {
						unique[key] = struct{}{}
					} else {
						rawCount++
					}
					break
				}
			}
		}
	}
	return len(unique) + rawCount, readable
}

func rpzHitFingerprint(line string, window int) (string, bool) {
	parts := strings.SplitN(line, " client ", 2)
	if len(parts) != 2 {
		return "", false
	}
	stamp := strings.TrimSpace(parts[0])
	if dot := strings.IndexByte(stamp, '.'); dot >= 0 {
		stamp = stamp[:dot]
	}
	when, err := time.Parse("02-Jan-2006 15:04:05", stamp)
	if err != nil {
		return "", false
	}
	clientParts := strings.SplitN(parts[1], " ", 3)
	if len(clientParts) < 3 {
		return "", false
	}
	client := strings.Split(clientParts[1], "#")[0]
	queryStart := strings.Index(clientParts[2], "(")
	queryEnd := strings.Index(clientParts[2], "):")
	if client == "" || queryStart < 0 || queryEnd <= queryStart {
		return "", false
	}
	queryName := clientParts[2][queryStart+1 : queryEnd]
	action := strings.TrimSpace(clientParts[2][queryEnd+2:])
	if queryName == "" || action == "" {
		return "", false
	}
	return fmt.Sprintf("%s|%s|%s|%d", client, queryName, action, when.Unix()/int64(window)), true
}

func configuredDNSAddress(node DNSNode) string {
	return node.Address
}

func probeDNSNode(ctx context.Context, address string) (string, error) {
	return probeDNSZone(ctx, address, rpzZoneName())
}

func probeDNSZone(ctx context.Context, address, zone string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", fmt.Errorf("DNS 节点地址为空")
	}
	if !dnsNodeAddressAllowed(address) {
		return "", fmt.Errorf("DNS 节点地址不在允许范围内")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = strings.Trim(address, "[]")
		port = "53"
	}
	if host == "" {
		return "", fmt.Errorf("DNS 节点地址无效")
	}
	zone = strings.TrimSpace(zone)
	if zone == "" || !domainPattern.MatchString(strings.TrimSuffix(zone, ".")) {
		return "", fmt.Errorf("DNS Zone 名称无效")
	}
	// RPZ health and publication checks query the authoritative zone data. Do
	// not let the recursive response-policy rewrite these control-plane
	// queries, especially when global deny is enabled.
	command := exec.CommandContext(ctx, "dig", "@"+host, "-p", port, "+norecurse", zone, "SOA", "+short", "+time=2", "+tries=1")
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("dig 失败: %s", strings.TrimSpace(string(output)))
	}
	fields := strings.Fields(string(output))
	if len(fields) < 3 {
		return "", fmt.Errorf("SOA 响应格式无效")
	}
	if _, err := strconv.ParseInt(fields[2], 10, 64); err != nil {
		return "", fmt.Errorf("SOA Serial 无效")
	}
	return fields[2], nil
}

func dnsHealthCacheTTL() time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(os.Getenv("DNS_HEALTH_CACHE_SECONDS")))
	if err != nil || seconds < 1 || seconds > 300 {
		seconds = 5
	}
	return time.Duration(seconds) * time.Second
}

func refreshDNSHealth() {
	if !dnsHealthRefreshing.CompareAndSwap(false, true) {
		return
	}
	defer dnsHealthRefreshing.Store(false)

	dnsMu.RLock()
	result := append([]DNSNode{}, state.Nodes...)
	dnsMu.RUnlock()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	primarySerial := ""
	for index := range result {
		result[index].Address = configuredDNSAddress(result[index])
		result[index].LastChecked = now
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		serial, err := probeDNSNode(ctx, result[index].Address)
		cancel()
		if err != nil {
			result[index].Status = "down"
			result[index].RPZVersion = "-"
			result[index].LastSync = "探测失败"
			continue
		}
		result[index].Status = "healthy"
		result[index].RPZVersion = serial
		result[index].LastSync = now
		if role, _ := dnsNodeRoleKind(result[index].Role); role == "primary" || result[index].ID == "primary-1" {
			primarySerial = serial
		}
	}
	if primarySerial != "" {
		for index := range result {
			if role, _ := dnsNodeRoleKind(result[index].Role); role == "secondary" && result[index].Status == "healthy" && result[index].RPZVersion != primarySerial {
				result[index].Status = "degraded"
				result[index].LastSync = "RPZ Serial 不一致"
			}
		}
	}
	dnsHealthMu.Lock()
	previous := append([]DNSNode{}, dnsHealthCache...)
	dnsHealthCache = append([]DNSNode{}, result...)
	dnsHealthAt = time.Now()
	dnsHealthMu.Unlock()
	previousStatus := make(map[string]string, len(previous))
	for _, node := range previous {
		previousStatus[node.ID] = node.Status
	}
	for _, node := range result {
		oldStatus := previousStatus[node.ID]
		name := node.Name
		if name == "" {
			name = node.ID
		}
		if node.Status == "down" && oldStatus != "down" {
			queueTelegramAlert("node_down", fmt.Sprintf("🚨 域盾 DNSGuard 节点不可达\n节点：%s\n地址：%s", name, node.Address))
		}
		if node.Status == "degraded" && oldStatus != "degraded" {
			queueTelegramAlert("node_degraded", fmt.Sprintf("⚠️ 域盾 DNSGuard 节点版本不一致\n节点：%s\nRPZ Serial：%s", name, node.RPZVersion))
		}
		if node.Status == "healthy" && (oldStatus == "down" || oldStatus == "degraded") {
			queueTelegramAlert("node_recovered", fmt.Sprintf("✅ 域盾 DNSGuard 节点已恢复\n节点：%s\nRPZ Serial：%s", name, node.RPZVersion))
		}
	}
}

func startDNSHealthMonitor() {
	interval := dnsHealthCacheTTL()
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("DNS_HEALTH_INTERVAL_SECONDS"))); err == nil && configured >= 1 && configured <= 300 {
		interval = time.Duration(configured) * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			refreshDNSHealth()
		}
	}()
}

func liveDNSNodes() []DNSNode {
	dnsHealthMu.Lock()
	cached := append([]DNSNode{}, dnsHealthCache...)
	refreshedAt := dnsHealthAt
	dnsHealthMu.Unlock()
	if len(cached) == 0 && dnsHealthRefreshing.Load() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && dnsHealthRefreshing.Load() {
			time.Sleep(10 * time.Millisecond)
			dnsHealthMu.Lock()
			cached = append([]DNSNode{}, dnsHealthCache...)
			refreshedAt = dnsHealthAt
			dnsHealthMu.Unlock()
			if len(cached) > 0 {
				return cached
			}
		}
	}
	if refreshedAt.IsZero() {
		refreshDNSHealth()
		dnsHealthMu.Lock()
		cached = append([]DNSNode{}, dnsHealthCache...)
		dnsHealthMu.Unlock()
		return cached
	}
	if time.Since(refreshedAt) >= dnsHealthCacheTTL() {
		go refreshDNSHealth()
	}
	return cached
}

func rpzRulesEqual(current, published []RPZRule) bool {
	if len(current) != len(published) {
		return false
	}
	currentByDomain := make(map[string]string, len(current))
	for _, rule := range current {
		currentByDomain[rule.Domain] = rpzRuleFingerprint(rule)
	}
	for _, rule := range published {
		if currentByDomain[rule.Domain] != rpzRuleFingerprint(rule) {
			return false
		}
	}
	return true
}

func rpzRuleType(rule RPZRule) string {
	if strings.EqualFold(strings.TrimSpace(rule.Type), "A") {
		return "A"
	}
	return "CNAME"
}

func rpzRuleFingerprint(rule RPZRule) string {
	return rule.Action + "\x00" + rpzRuleType(rule) + "\x00" + rule.Value + "\x00" + rule.Reason
}

func rpzRuleInSnapshot(rule RPZRule, snapshot []RPZRule) bool {
	for _, candidate := range snapshot {
		if candidate.Domain == rule.Domain && rpzRuleFingerprint(candidate) == rpzRuleFingerprint(rule) {
			return true
		}
	}
	return false
}

func rpzRuleSummary(rule RPZRule) string {
	reason := strings.TrimSpace(rule.Reason)
	if rpzRuleType(rule) == "A" {
		if reason == "" {
			return "A → " + rule.Value
		}
		return "A → " + rule.Value + " / " + reason
	}
	if reason == "" {
		return "白名单"
	}
	return "白名单 / " + reason
}

func rpzAuditDetail(rule RPZRule) string {
	detail := struct {
		Domain string `json:"domain"`
		Type   string `json:"type"`
		Value  string `json:"value,omitempty"`
		Reason string `json:"reason,omitempty"`
	}{Domain: rule.Domain, Type: rpzRuleType(rule), Value: rule.Value, Reason: rule.Reason}
	content, _ := json.Marshal(detail)
	return string(content)
}

func copyRPZRules(rules []RPZRule) []RPZRule {
	return append([]RPZRule{}, rules...)
}

func rpzPreviewSnapshot() (RPZChangeList []RPZChange, currentCount, publishedCount int) {
	RPZChangeList = make([]RPZChange, 0)
	dnsMu.RLock()
	current := copyRPZRules(state.Rules)
	published := copyRPZRules(state.Published)
	dnsMu.RUnlock()
	currentByDomain := make(map[string]RPZRule, len(current))
	publishedByDomain := make(map[string]RPZRule, len(published))
	for _, rule := range current {
		currentByDomain[rule.Domain] = rule
	}
	for _, rule := range published {
		publishedByDomain[rule.Domain] = rule
	}
	for domain, rule := range currentByDomain {
		old, exists := publishedByDomain[domain]
		if !exists {
			RPZChangeList = append(RPZChangeList, RPZChange{Type: "added", Domain: domain, After: rpzRuleSummary(rule)})
			continue
		}
		if rpzRuleFingerprint(old) != rpzRuleFingerprint(rule) {
			RPZChangeList = append(RPZChangeList, RPZChange{Type: "changed", Domain: domain, Before: rpzRuleSummary(old), After: rpzRuleSummary(rule)})
		}
	}
	for domain, rule := range publishedByDomain {
		if _, exists := currentByDomain[domain]; !exists {
			RPZChangeList = append(RPZChangeList, RPZChange{Type: "removed", Domain: domain, Before: rpzRuleSummary(rule)})
		}
	}
	sort.Slice(RPZChangeList, func(i, j int) bool { return RPZChangeList[i].Domain < RPZChangeList[j].Domain })
	return RPZChangeList, len(current), len(published)
}

func dnsStatePath() string {
	if path := os.Getenv("DNS_STATE_FILE"); path != "" {
		return path
	}
	return "dns-state.json"
}

func dnsNodeConfigPath() string {
	if path := os.Getenv("DNS_NODE_CONFIG_FILE"); path != "" {
		return path
	}
	return filepath.Join("config", "dns-nodes.json")
}

func withFileLock(path string, action func() error) error {
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return action()
}

func withStateFileLock(action func() error) error {
	stateFileMu.Lock()
	defer stateFileMu.Unlock()
	return withFileLock(dnsStatePath(), action)
}

func syncParentDir(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func nodeConfigsFromState() []DNSNodeConfig {
	dnsMu.RLock()
	defer dnsMu.RUnlock()
	configs := make([]DNSNodeConfig, 0, len(state.Nodes))
	for _, node := range state.Nodes {
		configs = append(configs, DNSNodeConfig{ID: node.ID, Name: node.Name, Role: node.Role, Address: node.Address})
	}
	return configs
}

func dnsNodeRoleKind(role string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "primary", "主节点", "隐藏主节点":
		return "primary", true
	case "secondary", "辅节点", "递归辅节点":
		return "secondary", true
	default:
		return "", false
	}
}

func validateDNSNodeSet(nodes []DNSNode) error {
	if len(nodes) == 0 {
		return fmt.Errorf("至少配置一个 DNS 节点")
	}
	primaryCount := 0
	seenIDs := make(map[string]struct{}, len(nodes))
	seenAddresses := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if strings.TrimSpace(node.ID) == "" || strings.TrimSpace(node.Name) == "" {
			return fmt.Errorf("DNS 节点名称和 ID 不能为空")
		}
		if _, ok := dnsNodeRoleKind(node.Role); !ok {
			return fmt.Errorf("DNS 节点 %s 的角色无效，只支持主节点或辅节点", node.Name)
		}
		if !dnsNodeAddressAllowed(node.Address) {
			return fmt.Errorf("DNS 节点 %s 地址无效或不在允许范围内", node.Name)
		}
		if _, ok := seenIDs[node.ID]; ok {
			return fmt.Errorf("DNS 节点 ID 重复: %s", node.ID)
		}
		seenIDs[node.ID] = struct{}{}
		address := strings.ToLower(strings.TrimSpace(node.Address))
		if _, ok := seenAddresses[address]; ok {
			return fmt.Errorf("DNS 节点地址重复: %s", node.Address)
		}
		seenAddresses[address] = struct{}{}
		if kind, _ := dnsNodeRoleKind(node.Role); kind == "primary" {
			primaryCount++
		}
	}
	if primaryCount != 1 {
		return fmt.Errorf("DNS 节点必须且只能有一个主节点")
	}
	return nil
}

func saveDNSNodeConfig() error {
	path := dnsNodeConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	nodeConfigFileMu.Lock()
	defer nodeConfigFileMu.Unlock()
	return withFileLock(path, func() error {
		content, err := json.MarshalIndent(nodeConfigsFromState(), "", "  ")
		if err != nil {
			return err
		}
		tmp := path + ".tmp"
		file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
		if err != nil {
			return err
		}
		if _, err := file.Write(content); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
		return syncParentDir(path)
	})
}

func loadDNSNodeConfig() error {
	path := dnsNodeConfigPath()
	content, err := os.ReadFile(path)
	if err == nil {
		var configs []DNSNodeConfig
		if err := json.Unmarshal(content, &configs); err != nil || len(configs) == 0 {
			if err == nil {
				err = fmt.Errorf("节点配置为空")
			}
			return fmt.Errorf("读取 DNS 节点配置失败: %w", err)
		}
		previous := make(map[string]DNSNode)
		dnsMu.RLock()
		for _, node := range state.Nodes {
			previous[node.ID] = node
		}
		dnsMu.RUnlock()
		nodes := make([]DNSNode, 0, len(configs))
		for _, config := range configs {
			node := previous[config.ID]
			node.ID, node.Name, node.Role, node.Address = config.ID, config.Name, config.Role, config.Address
			nodes = append(nodes, node)
		}
		if err := validateDNSNodeSet(nodes); err != nil {
			return fmt.Errorf("读取 DNS 节点配置失败: %w", err)
		}
		dnsMu.Lock()
		state.Nodes = nodes
		dnsMu.Unlock()
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("读取 DNS 节点配置失败: %w", err)
	}
	if !isInitialized() {
		// The first-run wizard owns node configuration. Do not materialize the
		// old placeholder nodes before the administrator has completed setup.
		return nil
	}
	for _, item := range strings.Split(os.Getenv("DNS_NODE_ADDRESSES"), ",") {
		parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || !dnsNodeAddressAllowed(parts[1]) {
			continue
		}
		dnsMu.Lock()
		for index := range state.Nodes {
			if state.Nodes[index].ID == strings.TrimSpace(parts[0]) {
				state.Nodes[index].Address = strings.TrimSpace(parts[1])
			}
		}
		dnsMu.Unlock()
	}
	return saveDNSNodeConfig()
}

func loadDNSState() error {
	path := dnsStatePath()
	content, contentErr := os.ReadFile(path)
	if contentErr == nil {
		var loaded dnsState
		if err := json.Unmarshal(content, &loaded); err == nil {
			if !isInitialized() {
				state = dnsState{Nodes: []DNSNode{}, Rules: []RPZRule{}, Published: []RPZRule{}, Versions: []RPZVersion{}}
				return nil
			}
			state = loaded
			return normalizeRuleIDs()
		}
	} else if !os.IsNotExist(contentErr) {
		return fmt.Errorf("读取 DNS 状态文件失败: %w", contentErr)
	}

	backup, backupErr := os.ReadFile(path + ".bak")
	if backupErr == nil {
		var loaded dnsState
		if err := json.Unmarshal(backup, &loaded); err == nil {
			state = loaded
			if err := saveDNSState(); err != nil {
				return fmt.Errorf("恢复 DNS 状态备份后写回失败: %w", err)
			}
			return normalizeRuleIDs()
		}
	} else if !os.IsNotExist(backupErr) {
		return fmt.Errorf("读取 DNS 状态备份失败: %w", backupErr)
	}

	if !os.IsNotExist(contentErr) || !os.IsNotExist(backupErr) {
		return fmt.Errorf("DNS 状态文件损坏且备份不可用: %s", path)
	}
	if !isInitialized() {
		state = dnsState{Nodes: []DNSNode{}, Rules: []RPZRule{}, Published: []RPZRule{}, Versions: []RPZVersion{}}
		return nil
	}

	state = dnsState{
		Nodes: []DNSNode{
			{ID: "primary-1", Name: "RPZ-PRIMARY", Role: "隐藏主节点", Address: "BIND_PRIMARY", Status: "healthy", RPZVersion: "RPZ_VERSION", LastSync: "刚刚"},
			{ID: "secondary-1", Name: "DNS-SECONDARY-1", Role: "递归辅节点", Address: "DNS_SECONDARY_1", Status: "healthy", RPZVersion: "RPZ_VERSION", LastSync: "刚刚"},
			{ID: "secondary-2", Name: "DNS-SECONDARY-2", Role: "递归辅节点", Address: "DNS_SECONDARY_2", Status: "healthy", RPZVersion: "RPZ_VERSION", LastSync: "刚刚"},
		},
		Rules:     []RPZRule{},
		Published: []RPZRule{},
		Versions:  []RPZVersion{},
	}
	if err := saveDNSState(); err != nil {
		return fmt.Errorf("初始化 DNS 状态文件失败: %w", err)
	}
	return nil
}

func normalizeRuleIDs() error {
	seen := make(map[string]bool)
	changed := false
	for index := range state.Rules {
		if state.Rules[index].ID == "" || seen[state.Rules[index].ID] {
			state.Rules[index].ID = nextRuleID()
			changed = true
		}
		seen[state.Rules[index].ID] = true
	}
	for index := range state.Published {
		if state.Published[index].ID == "" {
			state.Published[index].ID = nextRuleID()
			changed = true
		}
	}
	if changed {
		return saveDNSState()
	}
	return nil
}

func saveDNSState() error {
	path := dnsStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return withStateFileLock(func() error {
		dnsMu.RLock()
		content, err := json.MarshalIndent(state, "", "  ")
		dnsMu.RUnlock()
		if err != nil {
			return err
		}
		if previous, err := os.Open(path); err == nil {
			backup, backupErr := os.OpenFile(path+".bak", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
			if backupErr != nil {
				_ = previous.Close()
				return fmt.Errorf("创建 DNS 状态备份失败: %w", backupErr)
			}
			if _, backupErr = io.Copy(backup, previous); backupErr != nil {
				_ = backup.Close()
				_ = previous.Close()
				return fmt.Errorf("复制 DNS 状态备份失败: %w", backupErr)
			}
			if backupErr = backup.Sync(); backupErr != nil {
				_ = backup.Close()
				_ = previous.Close()
				return fmt.Errorf("同步 DNS 状态备份失败: %w", backupErr)
			}
			if backupErr = backup.Close(); backupErr != nil {
				_ = previous.Close()
				return fmt.Errorf("关闭 DNS 状态备份失败: %w", backupErr)
			}
			if backupErr = previous.Close(); backupErr != nil {
				return fmt.Errorf("关闭 DNS 状态文件失败: %w", backupErr)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("读取现有 DNS 状态文件失败: %w", err)
		}
		tmp := path + ".tmp"
		file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
		if err != nil {
			return err
		}
		if _, err := file.Write(content); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
		return syncParentDir(path)
	})
}

func dnsOverview(w http.ResponseWriter, _ *http.Request) {
	nodes := liveDNSNodes()
	dnsMu.RLock()
	rules := len(state.Rules)
	published := len(state.Published)
	pendingPublish := !rpzRulesEqual(state.Rules, state.Published)
	dnsMu.RUnlock()
	policyMode := effectivePolicyMode()
	rpzHits, rpzHitsReady := rpzHitCount()
	var rpzHitsValue any
	if rpzHitsReady {
		rpzHitsValue = rpzHits
	}
	healthy := 0
	for _, node := range nodes {
		if node.Status == "healthy" {
			healthy++
		}
	}
	rpzRuntime := rpzStatusSnapshot()
	latestJob, hasLatestJob := latestPublishJob()
	publishEvidenceReady := hasLatestJob && publishJobHasVerifiedCluster(latestJob, nodes)
	var publishEvidence any
	if hasLatestJob {
		publishEvidence = map[string]any{
			"id": latestJob.ID, "status": latestJob.Status, "syncStatus": latestJob.SyncStatus,
			"finishedAt": latestJob.FinishedAt, "nodeChecks": latestJob.NodeChecks,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":                len(nodes),
		"healthyNodes":         healthy,
		"rules":                rules,
		"publishedRules":       published,
		"pendingPublish":       pendingPublish,
		"rpzHits":              rpzHitsValue,
		"rpzHitStatus":         map[bool]string{true: "ready", false: "not_configured"}[rpzHitsReady],
		"lastSync":             time.Now().UTC().Format("15:04:05"),
		"publisherMode":        rpzRuntime.Mode,
		"policyMode":           policyMode,
		"globalDenyZone":       configuredGlobalDenyZone(),
		"lastPublish":          rpzRuntime.LastPublish,
		"publishMessage":       rpzRuntime.Message,
		"publishJobId":         rpzRuntime.JobID,
		"publishJobStatus":     rpzRuntime.JobStatus,
		"publishEvidenceReady": publishEvidenceReady,
		"publishEvidence":      publishEvidence,
	})
}

func rpzPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	changes, currentCount, publishedCount := rpzPreviewSnapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"pending":        len(changes) > 0,
		"currentCount":   currentCount,
		"publishedCount": publishedCount,
		"changes":        changes,
	})
}

func rpzVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	type versionSummary struct {
		ID        string `json:"id"`
		CreatedAt string `json:"createdAt"`
		Mode      string `json:"mode"`
		RuleCount int    `json:"ruleCount"`
	}
	dnsMu.RLock()
	result := make([]versionSummary, 0, len(state.Versions))
	for _, version := range state.Versions {
		result = append(result, versionSummary{ID: version.ID, CreatedAt: version.CreatedAt, Mode: version.Mode, RuleCount: len(version.Rules)})
	}
	dnsMu.RUnlock()
	writeJSON(w, http.StatusOK, result)
}

func dnsNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, liveDNSNodes())
	case http.MethodPost:
		var request struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Role    string `json:"role"`
			Address string `json:"address"`
		}
		if err := decodeJSON(r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
			return
		}
		request.ID = strings.TrimSpace(request.ID)
		request.Name = strings.TrimSpace(request.Name)
		request.Role = strings.TrimSpace(request.Role)
		request.Address = strings.TrimSpace(request.Address)
		if !dnsNodeAddressAllowed(request.Address) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "节点地址无效或不在允许范围内"})
			return
		}
		if request.ID == "" && (request.Name == "" || request.Role == "") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "新增节点必须填写名称和角色"})
			return
		}
		dnsMu.Lock()
		previousNodes := append([]DNSNode(nil), state.Nodes...)
		var auditNode DNSNode
		created := request.ID == ""
		if created {
			request.ID = nextNodeID()
		}
		for _, existing := range state.Nodes {
			if existing.ID != request.ID && strings.EqualFold(existing.Address, request.Address) {
				dnsMu.Unlock()
				writeJSON(w, http.StatusConflict, map[string]string{"error": "该节点地址已存在"})
				return
			}
		}
		updated := false
		for index := range state.Nodes {
			if state.Nodes[index].ID == request.ID {
				state.Nodes[index].Address = request.Address
				if request.Name != "" {
					state.Nodes[index].Name = request.Name
				}
				if request.Role != "" {
					state.Nodes[index].Role = request.Role
				}
				auditNode = state.Nodes[index]
				updated = true
				break
			}
		}
		if !updated {
			if request.Name == "" || request.Role == "" {
				dnsMu.Unlock()
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "新增节点必须填写名称和角色"})
				return
			}
			auditNode = DNSNode{ID: request.ID, Name: request.Name, Role: request.Role, Address: request.Address, Status: "unknown", RPZVersion: "—", LastSync: "未探测", LastChecked: "未检测"}
			state.Nodes = append(state.Nodes, auditNode)
			created = true
		}
		if err := validateDNSNodeSet(state.Nodes); err != nil {
			state.Nodes = previousNodes
			dnsMu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		dnsMu.Unlock()
		if err := saveDNSNodeConfig(); err != nil {
			dnsMu.Lock()
			state.Nodes = previousNodes
			dnsMu.Unlock()
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "节点配置保存失败"})
			return
		}
		dnsHealthMu.Lock()
		dnsHealthCache = nil
		dnsHealthAt = time.Time{}
		dnsHealthMu.Unlock()
		action := "dns.node.update"
		if created {
			action = "dns.node.create"
		}
		recordCriticalAudit(r, authUsername(), action, auditNode.Name+" / "+auditNode.Role+" / "+auditNode.Address)
		writeJSON(w, http.StatusOK, map[string]any{"updated": true, "created": created, "nodeId": request.ID, "address": request.Address})
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func dnsNodeByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/dns/nodes/"), "/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "节点 ID 不能为空"})
		return
	}
	dnsMu.Lock()
	if len(state.Nodes) <= 1 {
		dnsMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "至少保留一个 DNS 节点"})
		return
	}
	index := -1
	for i, node := range state.Nodes {
		if node.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		dnsMu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "节点不存在"})
		return
	}
	removed := state.Nodes[index]
	if role, _ := dnsNodeRoleKind(removed.Role); role == "primary" || removed.ID == "primary-1" {
		dnsMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "主节点不能直接删除，请先切换主节点角色"})
		return
	}
	previousNodes := append([]DNSNode(nil), state.Nodes...)
	state.Nodes = append(state.Nodes[:index], state.Nodes[index+1:]...)
	dnsMu.Unlock()
	if err := saveDNSNodeConfig(); err != nil {
		dnsMu.Lock()
		state.Nodes = previousNodes
		dnsMu.Unlock()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "节点配置保存失败"})
		return
	}
	dnsHealthMu.Lock()
	dnsHealthCache = nil
	dnsHealthAt = time.Time{}
	dnsHealthMu.Unlock()
	recordCriticalAudit(r, authUsername(), "dns.node.delete", removed.Name+" / "+removed.Role+" / "+removed.Address)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "nodeId": removed.ID})
}

func validDNSNodeAddress(address string) bool {
	address = strings.TrimSpace(address)
	if address == "" || strings.ContainsAny(address, " \t\r\n") {
		return false
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = strings.Trim(address, "[]")
		port = "53"
	}
	if host == "" {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber > 0 && portNumber <= 65535
}

func dnsNodeAllowedCIDRs() string {
	if configured := strings.TrimSpace(os.Getenv("DNS_NODE_ALLOWED_CIDRS")); configured != "" {
		return configured
	}
	return "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7"
}

func dnsNodeAddressAllowed(address string) bool {
	if !validDNSNodeAddress(address) {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(address), "[]")
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range strings.Split(dnsNodeAllowedCIDRs(), ",") {
			_, network, parseErr := net.ParseCIDR(strings.TrimSpace(cidr))
			if parseErr == nil && network.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, allowedHost := range strings.Split(os.Getenv("DNS_NODE_ALLOWED_HOSTS"), ",") {
		if strings.EqualFold(host, strings.TrimSpace(allowedHost)) && strings.TrimSpace(allowedHost) != "" {
			return true
		}
	}
	return false
}

func dnsRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	dnsMu.RLock()
	records := make([]RPZRecord, 0, len(state.Rules))
	for _, rule := range state.Rules {
		for _, trigger := range rpzQNAMETriggers(rule.Domain) {
			recordType := rpzRuleType(rule)
			recordValue := "rpz-passthru."
			policy := "QNAME / 白名单例外"
			if recordType == "A" {
				recordValue = rule.Value
				policy = "QNAME / A 记录重定向"
			}
			records = append(records, RPZRecord{
				Name:      trigger + "." + rpzZoneName() + ".",
				Type:      recordType,
				Value:     recordValue,
				Policy:    policy,
				Status:    rule.Status,
				UpdatedAt: rule.UpdatedAt,
			})
		}
	}
	dnsMu.RUnlock()
	writeJSON(w, http.StatusOK, records)
}

func dnsRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dnsMu.RLock()
		result := append([]RPZRule{}, state.Rules...)
		dnsMu.RUnlock()
		sort.SliceStable(result, func(i, j int) bool {
			if result[i].UpdatedAt != result[j].UpdatedAt {
				return result[i].UpdatedAt > result[j].UpdatedAt
			}
			return result[i].Domain < result[j].Domain
		})
		writeJSON(w, http.StatusOK, result)
	case http.MethodPost:
		var request struct {
			Domain string `json:"domain"`
			Type   string `json:"type"`
			Value  string `json:"value"`
			Reason string `json:"reason"`
		}
		if err := decodeJSON(r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
			return
		}
		request.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(request.Domain), "."))
		if !domainPattern.MatchString(request.Domain) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请输入合法域名"})
			return
		}
		request.Type = strings.ToUpper(strings.TrimSpace(request.Type))
		if request.Type == "" {
			request.Type = "CNAME"
		}
		if request.Type != "CNAME" && request.Type != "A" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "记录类型只支持 CNAME 或 A"})
			return
		}
		request.Value = strings.TrimSpace(request.Value)
		if request.Type == "A" {
			ip := net.ParseIP(request.Value)
			if ip == nil || ip.To4() == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "A 记录请输入合法 IPv4 地址"})
				return
			}
			request.Value = ip.To4().String()
		} else {
			request.Value = ""
		}
		now := time.Now().UTC().Format(time.RFC3339)
		action := "passthru"
		if request.Type == "A" {
			action = "redirect"
		}
		rule := RPZRule{ID: nextRuleID(), Domain: request.Domain, Action: action, Type: request.Type, Value: request.Value, Reason: strings.TrimSpace(request.Reason), Status: "draft", UpdatedAt: now}
		dnsStateMutationMu.Lock()
		dnsMu.Lock()
		for _, existing := range state.Rules {
			if existing.Domain == rule.Domain {
				dnsMu.Unlock()
				dnsStateMutationMu.Unlock()
				writeJSON(w, http.StatusConflict, map[string]string{"error": "该域名已有规则"})
				return
			}
		}
		previousRules := copyRPZRules(state.Rules)
		previousRevision := state.RulesRevision
		state.Rules = append(state.Rules, rule)
		state.RulesRevision++
		dnsMu.Unlock()
		if err := saveDNSState(); err != nil {
			dnsMu.Lock()
			state.Rules = previousRules
			state.RulesRevision = previousRevision
			dnsMu.Unlock()
			dnsStateMutationMu.Unlock()
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "规则保存失败"})
			return
		}
		dnsStateMutationMu.Unlock()
		recordCriticalAudit(r, authUsername(), "rpz.rule.create", rpzAuditDetail(rule))
		queueTelegramAlert("rpz_rule_create", rpzRuleTelegramMessage("新增规则", rule))
		writeJSON(w, http.StatusCreated, rule)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func dnsBulkRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var request struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(r, &request); err != nil || len(request.IDs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ids required"})
		return
	}
	selected := make(map[string]struct{}, len(request.IDs))
	for _, id := range request.IDs {
		if id = strings.TrimSpace(id); id != "" {
			selected[id] = struct{}{}
		}
	}
	if len(selected) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ids required"})
		return
	}
	dnsStateMutationMu.Lock()
	dnsMu.Lock()
	previousRules := copyRPZRules(state.Rules)
	previousRevision := state.RulesRevision
	kept := make([]RPZRule, 0, len(state.Rules))
	deleted := make([]RPZRule, 0, len(selected))
	for _, rule := range state.Rules {
		if _, ok := selected[rule.ID]; ok {
			deleted = append(deleted, rule)
			continue
		}
		kept = append(kept, rule)
	}
	state.Rules = kept
	if len(deleted) > 0 {
		state.RulesRevision++
	}
	dnsMu.Unlock()
	if len(deleted) == 0 {
		dnsStateMutationMu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "规则不存在"})
		return
	}
	if err := saveDNSState(); err != nil {
		dnsMu.Lock()
		state.Rules = previousRules
		state.RulesRevision = previousRevision
		dnsMu.Unlock()
		dnsStateMutationMu.Unlock()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "批量删除失败"})
		return
	}
	dnsStateMutationMu.Unlock()
	for _, rule := range deleted {
		recordCriticalAudit(r, authUsername(), "rpz.rule.delete", rpzAuditDetail(rule))
		queueTelegramAlert("rpz_rule_delete", rpzRuleTelegramMessage("批量删除规则", rule))
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": len(deleted)})
}

func dnsRuleByID(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/dns/rpz/"), "/")
	if id == "" {
		w.Header().Set("Allow", "DELETE, PUT")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if r.Method == http.MethodPut {
		var request struct {
			Domain string `json:"domain"`
			Type   string `json:"type"`
			Value  string `json:"value"`
			Reason string `json:"reason"`
		}
		if err := decodeJSON(r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
			return
		}
		request.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(request.Domain), "."))
		request.Type = strings.ToUpper(strings.TrimSpace(request.Type))
		request.Value = strings.TrimSpace(request.Value)
		if !domainPattern.MatchString(request.Domain) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请输入合法域名"})
			return
		}
		if request.Type == "" {
			request.Type = "CNAME"
		}
		if request.Type != "CNAME" && request.Type != "A" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "记录类型只支持 CNAME 或 A"})
			return
		}
		if request.Type == "A" {
			ip := net.ParseIP(request.Value)
			if ip == nil || ip.To4() == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "A 记录请输入合法 IPv4 地址"})
				return
			}
			request.Value = ip.To4().String()
		} else {
			request.Value = ""
		}
		action := "passthru"
		if request.Type == "A" {
			action = "redirect"
		}
		dnsStateMutationMu.Lock()
		dnsMu.Lock()
		index := -1
		for i, rule := range state.Rules {
			if rule.ID == id {
				index = i
				break
			}
		}
		if index < 0 {
			dnsMu.Unlock()
			dnsStateMutationMu.Unlock()
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "规则不存在"})
			return
		}
		for i, rule := range state.Rules {
			if i != index && rule.Domain == request.Domain {
				dnsMu.Unlock()
				dnsStateMutationMu.Unlock()
				writeJSON(w, http.StatusConflict, map[string]string{"error": "该域名已有规则"})
				return
			}
		}
		previous := state.Rules[index]
		previousRevision := state.RulesRevision
		updated := previous
		updated.Domain = request.Domain
		updated.Action = action
		updated.Type = request.Type
		updated.Value = request.Value
		updated.Reason = strings.TrimSpace(request.Reason)
		updated.Status = "draft"
		updated.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		state.Rules[index] = updated
		state.RulesRevision++
		dnsMu.Unlock()
		if err := saveDNSState(); err != nil {
			dnsMu.Lock()
			state.Rules[index] = previous
			state.RulesRevision = previousRevision
			dnsMu.Unlock()
			dnsStateMutationMu.Unlock()
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "规则保存失败"})
			return
		}
		dnsStateMutationMu.Unlock()
		recordCriticalAudit(r, authUsername(), "rpz.rule.update", rpzAuditDetail(updated))
		queueTelegramAlert("rpz_rule_update", rpzRuleTelegramMessage("编辑规则", updated))
		writeJSON(w, http.StatusOK, updated)
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE, PUT")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	dnsStateMutationMu.Lock()
	dnsMu.Lock()
	previousRules := copyRPZRules(state.Rules)
	previousRevision := state.RulesRevision
	index := -1
	for i, rule := range state.Rules {
		if rule.ID == id {
			index = i
			break
		}
	}
	var removed RPZRule
	if index >= 0 {
		removed = state.Rules[index]
		state.Rules = append(state.Rules[:index], state.Rules[index+1:]...)
		state.RulesRevision++
	}
	dnsMu.Unlock()
	if index < 0 {
		dnsStateMutationMu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "规则不存在"})
		return
	}
	if err := saveDNSState(); err != nil {
		dnsMu.Lock()
		state.Rules = previousRules
		state.RulesRevision = previousRevision
		dnsMu.Unlock()
		dnsStateMutationMu.Unlock()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "规则删除失败"})
		return
	}
	dnsStateMutationMu.Unlock()
	recordCriticalAudit(r, authUsername(), "rpz.rule.delete", rpzAuditDetail(removed))
	queueTelegramAlert("rpz_rule_delete", rpzRuleTelegramMessage("删除规则", removed))
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}
