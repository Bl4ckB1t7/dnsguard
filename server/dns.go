package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	Nodes     []DNSNode `json:"nodes"`
	Rules     []RPZRule `json:"rules"`
	Published []RPZRule `json:"published"`
}

var dnsMu sync.RWMutex
var state = dnsState{}
var domainPattern = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$`)
var dnsHealthMu sync.Mutex
var dnsHealthCache []DNSNode
var dnsHealthAt time.Time

func configuredDNSAddress(node DNSNode) string {
	for _, item := range strings.Split(os.Getenv("DNS_NODE_ADDRESSES"), ",") {
		parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == node.ID && strings.TrimSpace(parts[1]) != "" {
			return strings.TrimSpace(parts[1])
		}
	}
	return node.Address
}

func probeDNSNode(ctx context.Context, address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", fmt.Errorf("DNS 节点地址为空")
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
	now := time.Now().UTC().Format("2006-01-02 15:04:05Z")
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

func dnsStatePath() string {
	if path := os.Getenv("DNS_STATE_FILE"); path != "" {
		return path
	}
	return "dns-state.json"
}

func loadDNSState() {
	content, err := os.ReadFile(dnsStatePath())
	if err == nil && json.Unmarshal(content, &state) == nil {
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
	}
	_ = saveDNSState()
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func dnsOverview(w http.ResponseWriter, _ *http.Request) {
	nodes := liveDNSNodes()
	dnsMu.RLock()
	rules := len(state.Rules)
	published := len(state.Published)
	dnsMu.RUnlock()
	healthy := 0
	for _, node := range nodes {
		if node.Status == "healthy" {
			healthy++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":          len(nodes),
		"healthyNodes":   healthy,
		"rules":          rules,
		"publishedRules": published,
		"rpzHits":        0,
		"lastSync":       time.Now().UTC().Format("15:04:05Z"),
		"publisherMode":  rpzStatusSnapshot().Mode,
		"lastPublish":    rpzStatusSnapshot().LastPublish,
		"publishMessage": rpzStatusSnapshot().Message,
	})
}

func dnsNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, liveDNSNodes())
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
		sort.Slice(result, func(i, j int) bool { return result[i].UpdatedAt > result[j].UpdatedAt })
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
		rule := RPZRule{ID: "rule-" + strings.ReplaceAll(now, ":", ""), Domain: request.Domain, Action: "passthru", Reason: strings.TrimSpace(request.Reason), Status: "draft", UpdatedAt: now}
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
