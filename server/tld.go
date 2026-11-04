package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultTLDSourceURL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	maxTLDDocumentBytes = 256 * 1024
	maxTLDEntries       = 5000
)

type TLDStatus struct {
	Status             string `json:"status"`
	Source             string `json:"source"`
	Version            string `json:"version,omitempty"`
	LastUpdated        string `json:"lastUpdated,omitempty"`
	TLDCount           int    `json:"tldCount"`
	SHA256             string `json:"sha256,omitempty"`
	ETag               string `json:"etag,omitempty"`
	LastModified       string `json:"lastModified,omitempty"`
	LastChecked        string `json:"lastChecked,omitempty"`
	LastSuccessfulSync string `json:"lastSuccessfulSync,omitempty"`
	Message            string `json:"message,omitempty"`
}

var (
	tldStateMu sync.RWMutex
	tldState   = TLDStatus{Status: "not_configured", Source: defaultTLDSourceURL}
	tldSyncMu  sync.Mutex
	tldLabelRE = regexp.MustCompile(`^[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?$`)
)

func tldStatePath() string {
	if path := strings.TrimSpace(os.Getenv("TLD_STATE_FILE")); path != "" {
		return path
	}
	return filepath.Join(filepath.Dir(dnsStatePath()), "tld-state.json")
}

func tldSourceURL() string {
	if source := strings.TrimSpace(os.Getenv("TLD_SOURCE_URL")); source != "" {
		return source
	}
	return defaultTLDSourceURL
}

func tldSyncEnabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("TLD_DENY_ENABLED")))
	if value == "" {
		return true
	}
	return value == "1" || value == "true" || value == "yes"
}

func tldSyncInterval() time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(os.Getenv("TLD_SYNC_INTERVAL_SECONDS")))
	if err != nil || seconds < 300 || seconds > 7*24*60*60 {
		seconds = 24 * 60 * 60
	}
	return time.Duration(seconds) * time.Second
}

func tldSyncTimeout() time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(os.Getenv("TLD_SYNC_TIMEOUT_SECONDS")))
	if err != nil || seconds < 3 || seconds > 120 {
		seconds = 15
	}
	return time.Duration(seconds) * time.Second
}

func tldStatusSnapshot() TLDStatus {
	tldStateMu.RLock()
	defer tldStateMu.RUnlock()
	return tldState
}

func setTLDStatus(status TLDStatus) {
	tldStateMu.Lock()
	tldState = status
	tldStateMu.Unlock()
}

func loadTLDState() error {
	path := tldStatePath()
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		status := "pending"
		if !tldSyncEnabled() {
			status = "not_configured"
		}
		setTLDStatus(TLDStatus{Status: status, Source: tldSourceURL(), Message: "尚未完成首次同步"})
		return nil
	}
	if err != nil {
		setTLDStatus(TLDStatus{Status: "error", Source: tldSourceURL(), Message: fmt.Sprintf("读取 TLD 状态失败: %v", err)})
		return err
	}
	var loaded TLDStatus
	if err := json.Unmarshal(content, &loaded); err != nil {
		setTLDStatus(TLDStatus{Status: "error", Source: tldSourceURL(), Message: "TLD 状态文件损坏，等待重新同步"})
		return fmt.Errorf("TLD 状态文件损坏: %w", err)
	}
	if loaded.Source == "" {
		loaded.Source = tldSourceURL()
	}
	setTLDStatus(loaded)
	return nil
}

func saveTLDState(status TLDStatus) error {
	path := tldStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	content, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	return withFileLock(path, func() error {
		temporary, err := os.CreateTemp(filepath.Dir(path), ".dnsguard-tld-*.tmp")
		if err != nil {
			return err
		}
		temporaryName := temporary.Name()
		defer os.Remove(temporaryName)
		if err := temporary.Chmod(0o640); err != nil {
			_ = temporary.Close()
			return err
		}
		if _, err := temporary.Write(append(content, '\n')); err != nil {
			_ = temporary.Close()
			return err
		}
		if err := temporary.Sync(); err != nil {
			_ = temporary.Close()
			return err
		}
		if err := temporary.Close(); err != nil {
			return err
		}
		if err := os.Rename(temporaryName, path); err != nil {
			return err
		}
		return syncParentDir(path)
	})
}

func parseTLDDocument(content []byte) (version, lastUpdated, digest string, count int, err error) {
	lines := strings.Split(string(content), "\n")
	headerFound := false
	entries := make(map[string]struct{})
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "# Version ") {
				parts := strings.SplitN(strings.TrimPrefix(line, "# Version "), ", Last Updated ", 2)
				if len(parts) != 2 || !regexp.MustCompile(`^[0-9]+$`).MatchString(parts[0]) {
					return "", "", "", 0, fmt.Errorf("TLD 文件版本头无效")
				}
				version, lastUpdated, headerFound = parts[0], parts[1], true
			}
			continue
		}
		entry := strings.ToUpper(strings.TrimSuffix(line, "."))
		if !tldLabelRE.MatchString(entry) {
			return "", "", "", 0, fmt.Errorf("TLD 条目无效: %q", line)
		}
		if _, exists := entries[entry]; exists {
			return "", "", "", 0, fmt.Errorf("TLD 条目重复: %s", entry)
		}
		entries[entry] = struct{}{}
		if len(entries) > maxTLDEntries {
			return "", "", "", 0, fmt.Errorf("TLD 条目数量超过限制")
		}
	}
	if !headerFound {
		return "", "", "", 0, fmt.Errorf("TLD 文件缺少版本头")
	}
	if len(entries) == 0 {
		return "", "", "", 0, fmt.Errorf("TLD 文件没有有效条目")
	}
	digestBytes := sha256.Sum256(content)
	return version, lastUpdated, hex.EncodeToString(digestBytes[:]), len(entries), nil
}

func fetchTLDDocument(ctx context.Context, source string, previous TLDStatus) (TLDStatus, bool, error) {
	parsed, err := url.Parse(source)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && os.Getenv("APP_ENV") != "production")) {
		return TLDStatus{}, false, fmt.Errorf("TLD 来源必须使用 HTTPS")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return TLDStatus{}, false, err
	}
	if previous.ETag != "" {
		request.Header.Set("If-None-Match", previous.ETag)
	}
	if previous.LastModified != "" {
		request.Header.Set("If-Modified-Since", previous.LastModified)
	}
	response, err := (&http.Client{Timeout: tldSyncTimeout()}).Do(request)
	if err != nil {
		return TLDStatus{}, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		updated := previous
		updated.Status = "ready"
		updated.Source = source
		updated.LastChecked = time.Now().UTC().Format(time.RFC3339)
		updated.Message = "TLD 文件未变化"
		return updated, true, nil
	}
	if response.StatusCode != http.StatusOK {
		return TLDStatus{}, false, fmt.Errorf("TLD 来源返回 HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxTLDDocumentBytes+1))
	if err != nil {
		return TLDStatus{}, false, err
	}
	if len(content) > maxTLDDocumentBytes {
		return TLDStatus{}, false, fmt.Errorf("TLD 文件超过大小限制")
	}
	version, lastUpdated, digest, count, err := parseTLDDocument(content)
	if err != nil {
		return TLDStatus{}, false, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return TLDStatus{
		Status:             "ready",
		Source:             source,
		Version:            version,
		LastUpdated:        lastUpdated,
		TLDCount:           count,
		SHA256:             digest,
		ETag:               response.Header.Get("ETag"),
		LastModified:       response.Header.Get("Last-Modified"),
		LastChecked:        now,
		LastSuccessfulSync: now,
		Message:            "TLD 数据已校验；当前仅用于状态展示，未自动修改 BIND 配置或 RPZ",
	}, false, nil
}

func syncTLDNow(ctx context.Context) error {
	if !tldSyncEnabled() {
		setTLDStatus(TLDStatus{Status: "not_configured", Source: tldSourceURL(), Message: "TLD DENY 数据同步未启用"})
		return nil
	}
	tldSyncMu.Lock()
	defer tldSyncMu.Unlock()
	previous := tldStatusSnapshot()
	if previous.Source == "" {
		previous.Source = tldSourceURL()
	}
	updated, unchanged, err := fetchTLDDocument(ctx, tldSourceURL(), previous)
	if err != nil {
		failed := previous
		failed.Status = "error"
		failed.Source = tldSourceURL()
		failed.LastChecked = time.Now().UTC().Format(time.RFC3339)
		failed.Message = "TLD 同步失败，继续保留上一份有效状态：" + err.Error()
		setTLDStatus(failed)
		_ = saveTLDState(failed)
		return err
	}
	if unchanged {
		if err := saveTLDState(updated); err != nil {
			failed := previous
			failed.Status = "error"
			failed.Message = "TLD 状态持久化失败：" + err.Error()
			setTLDStatus(failed)
			return err
		}
		setTLDStatus(updated)
		return nil
	}
	if err := saveTLDState(updated); err != nil {
		failed := previous
		failed.Status = "error"
		failed.Message = "TLD 状态持久化失败：" + err.Error()
		setTLDStatus(failed)
		return err
	}
	setTLDStatus(updated)
	return nil
}

func startTLDSyncMonitor() {
	if !tldSyncEnabled() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), tldSyncTimeout())
		_ = syncTLDNow(ctx)
		cancel()
		ticker := time.NewTicker(tldSyncInterval())
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), tldSyncTimeout())
			_ = syncTLDNow(ctx)
			cancel()
		}
	}()
}

func tldStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, tldStatusSnapshot())
}
