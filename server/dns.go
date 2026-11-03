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
	ID         string `json:"id"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	Address    string `json:"address"`
	Status     string `json:"status"`
	RPZVersion string `json:"rpzVersion"`
	LastSync   string `json:"lastSync"`
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
	Nodes     []DNSNode    `json:"nodes"`
	Rules     []RPZRule    `json:"rules"`
	Published []RPZRule    `json:"published"`
	Versions  []RPZVersion `json:"versions"`
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
var ruleSequence atomic.Uint64
var stateFileMu sync.Mutex

func nextRuleID() string {
	return fmt.Sprintf("rule-%d-%d", time.Now().UTC().UnixNano(), ruleSequence.Add(1))
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
		content, err := os.ReadFile(path)
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
	command := exec.CommandContext(ctx, "dig", "@"+host, "-p", port, rpzZoneName(), "SOA", "+short", "+time=2", "+tries=1")
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

func liveDNSNodes() []DNSNode {
	dnsHealthMu.Lock()
	defer dnsHealthMu.Unlock()
	if len(dnsHealthCache) > 0 && time.Since(dnsHealthAt) < 5*time.Second {
		return append([]DNSNode{}, dnsHealthCache...)
	}
	dnsMu.RLock()
	result := append([]DNSNode{}, state.Nodes...)
	dnsMu.RUnlock()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	primarySerial := ""
	for index := range result {
		result[index].Address = configuredDNSAddress(result[index])
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
		if strings.Contains(result[index].Role, "主") || result[index].ID == "primary-1" {
			primarySerial = serial
		}
	}
	if primarySerial != "" {
		for index := range result {
			if strings.Contains(result[index].Role, "辅") && result[index].Status == "healthy" && result[index].RPZVersion != primarySerial {
				result[index].Status = "degraded"
				result[index].LastSync = "RPZ Serial 不一致"
			}
		}
	}
	dnsHealthCache = append([]DNSNode{}, result...)
	dnsHealthAt = time.Now()
	return result
}

func rpzRulesEqual(current, published []RPZRule) bool {
	if len(current) != len(published) {
		return false
	}
	currentByDomain := make(map[string]string, len(current))
	for _, rule := range current {
		currentByDomain[rule.Domain] = rule.Action + "\x00" + rule.Reason
	}
	for _, rule := range published {
		if currentByDomain[rule.Domain] != rule.Action+"\x00"+rule.Reason {
			return false
		}
	}
	return true
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
			RPZChangeList = append(RPZChangeList, RPZChange{Type: "added", Domain: domain, After: rule.Action + " / " + rule.Reason})
			continue
		}
		if old.Action != rule.Action || old.Reason != rule.Reason {
			RPZChangeList = append(RPZChangeList, RPZChange{Type: "changed", Domain: domain, Before: old.Action + " / " + old.Reason, After: rule.Action + " / " + rule.Reason})
		}
	}
	for domain, rule := range publishedByDomain {
		if _, exists := currentByDomain[domain]; !exists {
			RPZChangeList = append(RPZChangeList, RPZChange{Type: "removed", Domain: domain, Before: rule.Action + " / " + rule.Reason})
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

func nodeConfigsFromState() []DNSNodeConfig {
	dnsMu.RLock()
	defer dnsMu.RUnlock()
	configs := make([]DNSNodeConfig, 0, len(state.Nodes))
	for _, node := range state.Nodes {
		configs = append(configs, DNSNodeConfig{ID: node.ID, Name: node.Name, Role: node.Role, Address: node.Address})
	}
	return configs
}

func saveDNSNodeConfig() error {
	content, err := json.MarshalIndent(nodeConfigsFromState(), "", "  ")
	if err != nil {
		return err
	}
	path := dnsNodeConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return withFileLock(path, func() error {
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
		return os.Rename(tmp, path)
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
			if config.ID == "" || !dnsNodeAddressAllowed(config.Address) {
				return fmt.Errorf("读取 DNS 节点配置失败: 节点 %q 地址无效", config.ID)
			}
			node := previous[config.ID]
			node.ID, node.Name, node.Role, node.Address = config.ID, config.Name, config.Role, config.Address
			nodes = append(nodes, node)
		}
		dnsMu.Lock()
		state.Nodes = nodes
		dnsMu.Unlock()
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("读取 DNS 节点配置失败: %w", err)
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

func loadDNSState() {
	content, err := os.ReadFile(dnsStatePath())
	if err == nil && json.Unmarshal(content, &state) == nil {
		normalizeRuleIDs()
		return
	}
	backup, backupErr := os.ReadFile(dnsStatePath() + ".bak")
	if backupErr == nil && json.Unmarshal(backup, &state) == nil {
		_ = saveDNSState()
		return
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
	_ = saveDNSState()
}

func normalizeRuleIDs() {
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
		_ = saveDNSState()
	}
}

func saveDNSState() error {
	dnsMu.RLock()
	content, err := json.MarshalIndent(state, "", "  ")
	dnsMu.RUnlock()
	if err != nil {
		return err
	}
	path := dnsStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return withStateFileLock(func() error {
		if previous, err := os.Open(path); err == nil {
			backup, backupErr := os.Create(path + ".bak")
			if backupErr == nil {
				_, _ = io.Copy(backup, previous)
				_ = backup.Sync()
				_ = backup.Close()
			}
			_ = previous.Close()
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
		return os.Rename(tmp, path)
	})
}

func dnsOverview(w http.ResponseWriter, _ *http.Request) {
	nodes := liveDNSNodes()
	dnsMu.RLock()
	rules := len(state.Rules)
	published := len(state.Published)
	pendingPublish := !rpzRulesEqual(state.Rules, state.Published)
	dnsMu.RUnlock()
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
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":            len(nodes),
		"healthyNodes":     healthy,
		"rules":            rules,
		"publishedRules":   published,
		"pendingPublish":   pendingPublish,
		"rpzHits":          rpzHitsValue,
		"rpzHitStatus":     map[bool]string{true: "ready", false: "not_configured"}[rpzHitsReady],
		"lastSync":         time.Now().UTC().Format("15:04:05"),
		"publisherMode":    rpzRuntime.Mode,
		"lastPublish":      rpzRuntime.LastPublish,
		"publishMessage":   rpzRuntime.Message,
		"publishJobId":     rpzRuntime.JobID,
		"publishJobStatus": rpzRuntime.JobStatus,
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
		if err := decodeJSON(r, &request); err != nil || strings.TrimSpace(request.ID) == "" || !dnsNodeAddressAllowed(request.Address) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "节点 ID 或地址无效"})
			return
		}
		dnsMu.Lock()
		updated := false
		for index := range state.Nodes {
			if state.Nodes[index].ID == request.ID {
				state.Nodes[index].Address = strings.TrimSpace(request.Address)
				if strings.TrimSpace(request.Name) != "" {
					state.Nodes[index].Name = strings.TrimSpace(request.Name)
				}
				if strings.TrimSpace(request.Role) != "" {
					state.Nodes[index].Role = strings.TrimSpace(request.Role)
				}
				updated = true
				break
			}
		}
		dnsMu.Unlock()
		if !updated {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "节点不存在"})
			return
		}
		if err := saveDNSNodeConfig(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "节点配置保存失败"})
			return
		}
		dnsHealthMu.Lock()
		dnsHealthCache = nil
		dnsHealthMu.Unlock()
		auditEvent(r, authUsername(), "dns.node.update", request.ID+":"+request.Address)
		writeJSON(w, http.StatusOK, map[string]any{"updated": true, "nodeId": request.ID, "address": request.Address})
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
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
			records = append(records, RPZRecord{
				Name:      trigger + "." + rpzZoneName() + ".",
				Type:      "CNAME",
				Value:     "rpz-passthru.",
				Policy:    "QNAME / 白名单例外",
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
		if strings.TrimSpace(request.Reason) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请填写加白原因"})
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		rule := RPZRule{ID: nextRuleID(), Domain: request.Domain, Action: "passthru", Reason: strings.TrimSpace(request.Reason), Status: "draft", UpdatedAt: now}
		dnsMu.Lock()
		for _, existing := range state.Rules {
			if existing.Domain == rule.Domain {
				dnsMu.Unlock()
				writeJSON(w, http.StatusConflict, map[string]string{"error": "该域名已有规则"})
				return
			}
		}
		state.Rules = append(state.Rules, rule)
		dnsMu.Unlock()
		if err := saveDNSState(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "规则保存失败"})
			return
		}
		auditEvent(r, authUsername(), "rpz.rule.create", rule.Domain)
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
	dnsMu.Lock()
	kept := make([]RPZRule, 0, len(state.Rules))
	deleted := make([]string, 0, len(selected))
	for _, rule := range state.Rules {
		if _, ok := selected[rule.ID]; ok {
			deleted = append(deleted, rule.ID)
			continue
		}
		kept = append(kept, rule)
	}
	state.Rules = kept
	dnsMu.Unlock()
	if len(deleted) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "规则不存在"})
		return
	}
	if err := saveDNSState(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "批量删除失败"})
		return
	}
	for _, id := range deleted {
		auditEvent(r, authUsername(), "rpz.rule.delete", id)
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": len(deleted)})
}

func dnsRuleByID(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/dns/rpz/"), "/")
	if id == "" || r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	dnsMu.Lock()
	index := -1
	for i, rule := range state.Rules {
		if rule.ID == id {
			index = i
			break
		}
	}
	if index >= 0 {
		state.Rules = append(state.Rules[:index], state.Rules[index+1:]...)
	}
	dnsMu.Unlock()
	if index < 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "规则不存在"})
		return
	}
	if err := saveDNSState(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "规则删除失败"})
		return
	}
	auditEvent(r, authUsername(), "rpz.rule.delete", id)
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}
