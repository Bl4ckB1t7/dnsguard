package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	dnsMu.RLock()
	defer dnsMu.RUnlock()
	healthy := 0
	for _, node := range state.Nodes {
		if node.Status == "healthy" {
			healthy++
		}
	}
	published := len(state.Published)
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":          len(state.Nodes),
		"healthyNodes":   healthy,
		"rules":          len(state.Rules),
		"publishedRules": published,
		"rpzHits":        0,
		"lastSync":       "刚刚",
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
	dnsMu.RLock()
	result := append([]DNSNode(nil), state.Nodes...)
	dnsMu.RUnlock()
	writeJSON(w, http.StatusOK, result)
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
