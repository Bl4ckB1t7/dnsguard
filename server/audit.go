package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
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
var auditHealthMu sync.RWMutex
var auditIntegrityFailure string

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

func setAuditIntegrityFailure(err error) {
	auditHealthMu.Lock()
	defer auditHealthMu.Unlock()
	if err == nil {
		auditIntegrityFailure = ""
		return
	}
	auditIntegrityFailure = err.Error()
}

func auditIntegrityError() error {
	auditHealthMu.RLock()
	reason := auditIntegrityFailure
	auditHealthMu.RUnlock()
	if reason == "" {
		return nil
	}
	return fmt.Errorf("审计文件处于异常状态: %s", reason)
}

func loadAudit() error {
	content, err := os.ReadFile(auditFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			setAuditIntegrityFailure(nil)
			return nil
		}
		wrapped := fmt.Errorf("读取审计文件失败: %w", err)
		setAuditIntegrityFailure(wrapped)
		return wrapped
	}
	var loaded []AuditEntry
	if json.Unmarshal(content, &loaded) == nil && validAuditChain(loaded) && validAuditRotationBoundary(auditFilePath(), loaded) {
		auditMu.Lock()
		auditEntries = loaded
		if len(auditEntries) > auditMaxEntries() {
			auditEntries = auditEntries[len(auditEntries)-auditMaxEntries():]
		}
		auditMu.Unlock()
		setAuditIntegrityFailure(nil)
		return nil
	}
	wrapped := fmt.Errorf("审计文件格式或哈希链校验失败: %s", auditFilePath())
	setAuditIntegrityFailure(wrapped)
	log.Printf("audit file failed integrity validation: %s", auditFilePath())
	return wrapped
}

func validAuditRotationBoundary(path string, entries []AuditEntry) bool {
	if len(entries) == 0 || entries[0].PrevHash == "" {
		return true
	}
	// A bounded audit file can start in the middle of a chain without a
	// rotation sidecar. Its first retained entry is still internally verified;
	// the external boundary is intentionally unrecoverable from this file alone.
	if len(entries) >= auditMaxEntries() {
		return true
	}
	content, err := os.ReadFile(path + ".1")
	if err != nil {
		return false
	}
	var previous []AuditEntry
	if json.Unmarshal(content, &previous) != nil || !validAuditChain(previous) || len(previous) == 0 {
		return false
	}
	return previous[len(previous)-1].Hash == entries[0].PrevHash
}

func validAuditChain(entries []AuditEntry) bool {
	for index, entry := range entries {
		if entry.Hash == "" || auditHash(entry) != entry.Hash {
			return false
		}
		if index > 0 && entry.PrevHash != entries[index-1].Hash {
			return false
		}
	}
	return true
}

func auditEvent(r *http.Request, actor, action, result string) error {
	if err := auditIntegrityError(); err != nil {
		return err
	}
	auditFileMu.Lock()
	defer auditFileMu.Unlock()
	if err := auditIntegrityError(); err != nil {
		return err
	}
	path := auditFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("创建审计目录失败: %w", err)
	}
	if err := withFileLock(path, func() error {
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
		auditMu.RLock()
		previousHash := ""
		if len(auditEntries) > 0 {
			previousHash = auditEntries[len(auditEntries)-1].Hash
		}
		entries := append([]AuditEntry(nil), auditEntries...)
		auditMu.RUnlock()
		if rotated {
			entries = nil
		}
		entry := AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339), Actor: actor, Action: action, Result: result, IP: ip, PrevHash: previousHash}
		entry.Hash = auditHash(entry)
		entries = append(entries, entry)
		if len(entries) > auditMaxEntries() {
			entries = entries[len(entries)-auditMaxEntries():]
		}
		content, marshalErr := json.MarshalIndent(entries, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		temporary := path + ".tmp"
		if err := os.WriteFile(temporary, content, 0o640); err != nil {
			return err
		}
		if err := os.Rename(temporary, path); err != nil {
			return err
		}
		if err := syncParentDir(path); err != nil {
			return err
		}
		auditMu.Lock()
		auditEntries = entries
		auditMu.Unlock()
		return nil
	}); err != nil {
		log.Printf("audit event write failed: action=%s result=%s error=%v", action, result, err)
		setAuditIntegrityFailure(fmt.Errorf("审计写入失败: %w", err))
		return err
	}
	return nil
}

// recordCriticalAudit keeps the business result visible while making an audit
// persistence failure operationally visible instead of silently discarding it.
func recordCriticalAudit(r *http.Request, actor, action, result string) error {
	if err := auditEvent(r, actor, action, result); err != nil {
		log.Printf("critical audit unavailable: action=%s result=%s error=%v", action, result, err)
		queueTelegramAlert("audit_write_failed", fmt.Sprintf("🚨 域盾 DNSGuard 审计写入失败\n动作：%s\n结果：%s\n原因：%s", action, result, err.Error()))
		return err
	}
	return nil
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
