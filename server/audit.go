package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Result    string `json:"result"`
	IP        string `json:"ip,omitempty"`
	PrevHash  string `json:"prevHash,omitempty"`
	Hash      string `json:"hash,omitempty"`
}

var auditMu sync.RWMutex
var auditEntries []AuditEntry
var auditFileMu sync.Mutex

func auditFilePath() string {
	if path := os.Getenv("AUDIT_FILE"); path != "" {
		return path
	}
	return "audit.json"
}

func auditMaxEntries() int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv("AUDIT_MAX_ENTRIES")))
	if err != nil || value < 100 || value > 100000 {
		return 2000
	}
	return value
}

func auditRotateBytes() int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("AUDIT_ROTATE_BYTES")), 10, 64)
	if err != nil || value < 0 {
		return 5 * 1024 * 1024
	}
	return value
}

func auditRotateBackups() int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv("AUDIT_ROTATE_BACKUPS")))
	if err != nil || value < 1 || value > 20 {
		return 3
	}
	return value
}

func auditHash(entry AuditEntry) string {
	payload := struct {
		Timestamp string `json:"timestamp"`
		Actor     string `json:"actor"`
		Action    string `json:"action"`
		Result    string `json:"result"`
		IP        string `json:"ip,omitempty"`
		PrevHash  string `json:"prevHash,omitempty"`
	}{entry.Timestamp, entry.Actor, entry.Action, entry.Result, entry.IP, entry.PrevHash}
	content, _ := json.Marshal(payload)
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func rotateAuditFiles(path string) error {
	backups := auditRotateBackups()
	for index := backups - 1; index >= 1; index-- {
		oldPath := path + "." + strconv.Itoa(index)
		newPath := path + "." + strconv.Itoa(index+1)
		if err := os.Rename(oldPath, newPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Rename(path, path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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
		if len(auditEntries) > auditMaxEntries() {
			auditEntries = auditEntries[len(auditEntries)-auditMaxEntries():]
		}
		auditMu.Unlock()
	}
}

func auditEvent(r *http.Request, actor, action, result string) {
	auditFileMu.Lock()
	defer auditFileMu.Unlock()
	path := auditFilePath()
	if os.MkdirAll(filepath.Dir(path), 0o755) != nil {
		return
	}
	_ = withFileLock(path, func() error {
		rotated := false
		if limit := auditRotateBytes(); limit > 0 {
			if info, err := os.Stat(path); err == nil && info.Size() >= limit {
				if err := rotateAuditFiles(path); err != nil {
					return err
				}
				rotated = true
			}
		}
		ip := requestIP(r)
		auditMu.Lock()
		previousHash := ""
		if len(auditEntries) > 0 {
			previousHash = auditEntries[len(auditEntries)-1].Hash
		}
		if rotated {
			auditEntries = nil
		}
		entry := AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339), Actor: actor, Action: action, Result: result, IP: ip, PrevHash: previousHash}
		entry.Hash = auditHash(entry)
		auditEntries = append(auditEntries, entry)
		if len(auditEntries) > auditMaxEntries() {
			auditEntries = auditEntries[len(auditEntries)-auditMaxEntries():]
		}
		content, marshalErr := json.MarshalIndent(auditEntries, "", "  ")
		auditMu.Unlock()
		if marshalErr != nil {
			return marshalErr
		}
		temporary := path + ".tmp"
		if err := os.WriteFile(temporary, content, 0o640); err != nil {
			return err
		}
		return os.Rename(temporary, path)
	})
}

func audit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	query := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))
	actor := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("actor")))
	action := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("action")))
	page := positiveQueryInt(r.URL.Query().Get("page"), 1)
	pageSize := positiveQueryInt(r.URL.Query().Get("pageSize"), 50)
	if pageSize > 200 {
		pageSize = 200
	}
	auditMu.RLock()
	filtered := make([]AuditEntry, 0, len(auditEntries))
	for _, entry := range auditEntries {
		searchText := strings.ToLower(strings.Join([]string{entry.Actor, entry.Action, entry.Result, entry.IP}, " "))
		if query != "" && !strings.Contains(searchText, query) {
			continue
		}
		if actor != "" && !strings.Contains(strings.ToLower(entry.Actor), actor) {
			continue
		}
		if action != "" && !strings.Contains(strings.ToLower(entry.Action), action) {
			continue
		}
		filtered = append(filtered, entry)
	}
	auditMu.RUnlock()
	// The audit file is append-only, but operators need the newest event first
	// when opening page 1 after a change is made.
	ordered := make([]AuditEntry, 0, len(filtered))
	for index := len(filtered) - 1; index >= 0; index-- {
		ordered = append(ordered, filtered[index])
	}
	start := (page - 1) * pageSize
	if start > len(ordered) {
		start = len(ordered)
	}
	end := start + pageSize
	if end > len(ordered) {
		end = len(ordered)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":    ordered[start:end],
		"total":    len(ordered),
		"page":     page,
		"pageSize": pageSize,
	})
}

func positiveQueryInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return fallback
	}
	return parsed
}
