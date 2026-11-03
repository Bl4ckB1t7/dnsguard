package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Result    string `json:"result"`
	IP        string `json:"ip,omitempty"`
}

var auditMu sync.RWMutex
var auditEntries []AuditEntry

func auditFilePath() string {
	if path := os.Getenv("AUDIT_FILE"); path != "" {
		return path
	}
	return "audit.json"
}

func loadAudit() {
	content, err := os.ReadFile(auditFilePath())
	if err != nil {
		return
	}
	var loaded []AuditEntry
	if json.Unmarshal(content, &loaded) == nil {
		auditMu.Lock()
		auditEntries = loaded
		if len(auditEntries) > 2000 {
			auditEntries = auditEntries[len(auditEntries)-2000:]
		}
		auditMu.Unlock()
	}
}

func auditEvent(r *http.Request, actor, action, result string) {
	ip := requestIP(r)
	entry := AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339), Actor: actor, Action: action, Result: result, IP: ip}
	auditMu.Lock()
	auditEntries = append(auditEntries, entry)
	if len(auditEntries) > 2000 {
		auditEntries = auditEntries[len(auditEntries)-2000:]
	}
	content, marshalErr := json.MarshalIndent(auditEntries, "", "  ")
	auditMu.Unlock()
	if marshalErr != nil {
		return
	}
	path := auditFilePath()
	if os.MkdirAll(filepath.Dir(path), 0o755) != nil {
		return
	}
	temporary := path + ".tmp"
	if os.WriteFile(temporary, content, 0o640) == nil {
		_ = os.Rename(temporary, path)
	}
}

func audit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	auditMu.RLock()
	entries := append([]AuditEntry(nil), auditEntries...)
	auditMu.RUnlock()
	writeJSON(w, http.StatusOK, entries)
}
