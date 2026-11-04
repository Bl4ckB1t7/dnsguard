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
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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
	Status              string   `json:"status"`
	Source              string   `json:"source"`
	Version             string   `json:"version,omitempty"`
	LastUpdated         string   `json:"lastUpdated,omitempty"`
	TLDCount            int      `json:"tldCount"`
	SHA256              string   `json:"sha256,omitempty"`
	ETag                string   `json:"etag,omitempty"`
	LastModified        string   `json:"lastModified,omitempty"`
	LastChecked         string   `json:"lastChecked,omitempty"`
	LastSuccessfulSync  string   `json:"lastSuccessfulSync,omitempty"`
	Message             string   `json:"message,omitempty"`
	PolicyStatus        string   `json:"policyStatus,omitempty"`
	PolicySerial        string   `json:"policySerial,omitempty"`
	PolicyLastPublished string   `json:"policyLastPublished,omitempty"`
	PolicyMessage       string   `json:"policyMessage,omitempty"`
	TLDs                []string `json:"-"`
}

type tldStateFile struct {
	TLDStatus
	TLDs []string `json:"tlds,omitempty"`
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

func tldPolicyPublishEnabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("TLD_DENY_PUBLISH_ENABLED")))
	return value == "1" || value == "true" || value == "yes"
}

func tldPolicyZone() string {
	return strings.TrimSuffix(strings.TrimSpace(os.Getenv("TLD_DENY_ZONE")), ".")
}

func tldPolicyTTL() int {
	ttl, err := strconv.Atoi(strings.TrimSpace(os.Getenv("TLD_DENY_TTL_SECONDS")))
	if err != nil || ttl < 30 || ttl > 86400 {
		return 300
	}
	return ttl
}

func tldPolicyArtifactPath() string {
	if path := strings.TrimSpace(os.Getenv("TLD_DENY_ARTIFACT_FILE")); path != "" {
		return path
	}
	return filepath.Join(filepath.Dir(dnsStatePath()), "rpz", tldPolicyZone()+".db")
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
	var persisted tldStateFile
	if err := json.Unmarshal(content, &persisted); err != nil {
		setTLDStatus(TLDStatus{Status: "error", Source: tldSourceURL(), Message: "TLD 状态文件损坏，等待重新同步"})
		return fmt.Errorf("TLD 状态文件损坏: %w", err)
	}
	loaded := persisted.TLDStatus
	loaded.TLDs = append([]string(nil), persisted.TLDs...)
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
	content, err := json.MarshalIndent(tldStateFile{TLDStatus: status, TLDs: status.TLDs}, "", "  ")
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

func parseTLDDocumentWithEntries(content []byte) (version, lastUpdated, digest string, count int, entriesList []string, err error) {
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
					return "", "", "", 0, nil, fmt.Errorf("TLD 文件版本头无效")
				}
				version, lastUpdated, headerFound = parts[0], parts[1], true
			}
			continue
		}
		entry := strings.ToUpper(strings.TrimSuffix(line, "."))
		if !tldLabelRE.MatchString(entry) {
			return "", "", "", 0, nil, fmt.Errorf("TLD 条目无效: %q", line)
		}
		if _, exists := entries[entry]; exists {
			return "", "", "", 0, nil, fmt.Errorf("TLD 条目重复: %s", entry)
		}
		entries[entry] = struct{}{}
		if len(entries) > maxTLDEntries {
			return "", "", "", 0, nil, fmt.Errorf("TLD 条目数量超过限制")
		}
	}
	if !headerFound {
		return "", "", "", 0, nil, fmt.Errorf("TLD 文件缺少版本头")
	}
	if len(entries) == 0 {
		return "", "", "", 0, nil, fmt.Errorf("TLD 文件没有有效条目")
	}
	entriesList = make([]string, 0, len(entries))
	for entry := range entries {
		entriesList = append(entriesList, entry)
	}
	sort.Strings(entriesList)
	digestBytes := sha256.Sum256(content)
	return version, lastUpdated, hex.EncodeToString(digestBytes[:]), len(entries), entriesList, nil
}

func parseTLDDocument(content []byte) (version, lastUpdated, digest string, count int, err error) {
	version, lastUpdated, digest, count, _, err = parseTLDDocumentWithEntries(content)
	return
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
	version, lastUpdated, digest, count, entries, err := parseTLDDocumentWithEntries(content)
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
		TLDs:               entries,
		Message:            "TLD 数据已校验；默认拒绝 RPZ 仅在显式配置并验证后发布",
	}, false, nil
}

var (
	tldPolicySerialMu   sync.Mutex
	lastTLDPolicySerial int64
	runTLDNSUpdateFunc  = runTLDNSUpdate
)

func normalizeTLDEntries(entries []string) ([]string, error) {
	seen := make(map[string]struct{}, len(entries))
	result := make([]string, 0, len(entries))
	for _, raw := range entries {
		entry := strings.ToUpper(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if !tldLabelRE.MatchString(entry) {
			return nil, fmt.Errorf("TLD 条目无效: %q", raw)
		}
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		result = append(result, entry)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("TLD 列表为空")
	}
	sort.Strings(result)
	return result, nil
}

func nextTLDPolicySerial() int64 {
	tldPolicySerialMu.Lock()
	defer tldPolicySerialMu.Unlock()
	serial := time.Now().UTC().Unix()
	if serial <= lastTLDPolicySerial {
		serial = lastTLDPolicySerial + 1
	}
	lastTLDPolicySerial = serial
	return serial
}

func compileTLDPolicy(entries []string) (string, error) {
	zone := tldPolicyZone()
	if !domainPattern.MatchString(zone) {
		return "", fmt.Errorf("TLD_DENY_ZONE 无效: %q", zone)
	}
	normalized, err := normalizeTLDEntries(entries)
	if err != nil {
		return "", err
	}
	ttl := tldPolicyTTL()
	var builder strings.Builder
	fmt.Fprintf(&builder, "$TTL %d\n$ORIGIN %s.\n@ SOA localhost. hostmaster.localhost. (%d 1h 15m 30d %d)\n  NS localhost.\n\n", ttl, zone, nextTLDPolicySerial(), ttl)
	for _, entry := range normalized {
		label := strings.ToLower(entry)
		fmt.Fprintf(&builder, "%s.%s. %d CNAME .\n", label, zone, ttl)
		fmt.Fprintf(&builder, "*.%s.%s. %d CNAME .\n", label, zone, ttl)
	}
	return builder.String(), nil
}

func writeTLDPolicyArtifact(content string) (string, error) {
	path := tldPolicyArtifactPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".dnsguard-tld-policy-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o640); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if _, err := temporary.WriteString(content); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return "", err
	}
	if err := syncParentDir(path); err != nil {
		return "", err
	}
	return path, nil
}

func validateTLDPolicy(ctx context.Context, path string) error {
	checker, err := exec.LookPath("named-checkzone")
	if err != nil {
		return nil
	}
	command := exec.CommandContext(ctx, checker, tldPolicyZone(), path)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("named-checkzone 失败: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func runTLDNSUpdate(ctx context.Context, current, previous []string) error {
	server := rpzConfig("RPZ_PRIMARY", "")
	port := rpzConfig("RPZ_PRIMARY_PORT", "53")
	keyFile := strings.TrimSpace(os.Getenv("RPZ_KEY_FILE"))
	zone := tldPolicyZone()
	if server == "" || keyFile == "" || zone == "" {
		return fmt.Errorf("TLD DENY 发布缺少 RPZ_PRIMARY、RPZ_KEY_FILE 或 TLD_DENY_ZONE")
	}
	info, err := os.Stat(keyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("RPZ_KEY_FILE 不可安全读取")
	}
	normalizedCurrent, err := normalizeTLDEntries(current)
	if err != nil {
		return err
	}
	normalizedPrevious, err := normalizeTLDEntries(previous)
	if err != nil && len(previous) > 0 {
		return err
	}
	var input strings.Builder
	fmt.Fprintf(&input, "server %s %s\nzone %s\n", server, port, zone)
	for _, entry := range normalizedPrevious {
		label := strings.ToLower(entry)
		fmt.Fprintf(&input, "update delete %s.%s. CNAME\n", label, zone)
		fmt.Fprintf(&input, "update delete *.%s.%s. CNAME\n", label, zone)
	}
	for _, entry := range normalizedCurrent {
		label := strings.ToLower(entry)
		fmt.Fprintf(&input, "update add %s.%s. %d CNAME .\n", label, zone, tldPolicyTTL())
		fmt.Fprintf(&input, "update add *.%s.%s. %d CNAME .\n", label, zone, tldPolicyTTL())
	}
	input.WriteString("send\n")
	command := exec.CommandContext(ctx, "nsupdate", "-k", keyFile) // #nosec G702 -- executable is fixed and keyFile is protected deployment configuration.
	command.Stdin = strings.NewReader(input.String())
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("TLD DENY nsupdate 失败: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func queryTLDPolicySerial(ctx context.Context) (string, error) {
	server := rpzConfig("RPZ_PRIMARY", "")
	port := rpzConfig("RPZ_PRIMARY_PORT", "53")
	if server == "" {
		return "", fmt.Errorf("RPZ_PRIMARY 未配置")
	}
	command := exec.CommandContext(ctx, "dig", "@"+server, "-p", port, tldPolicyZone(), "SOA", "+short", "+time=2", "+tries=1")
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("TLD DENY SOA 查询失败")
	}
	fields := strings.Fields(string(output))
	if len(fields) < 3 || fields[2] == "" {
		return "", fmt.Errorf("TLD DENY SOA Serial 无效")
	}
	return fields[2], nil
}

func tldEntriesEqual(left, right []string) bool {
	a, errA := normalizeTLDEntries(left)
	b, errB := normalizeTLDEntries(right)
	if len(left) == 0 && len(right) == 0 {
		return true
	}
	if errA != nil || errB != nil || len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func publishTLDPolicy(ctx context.Context, current, previous []string) (string, error) {
	content, err := compileTLDPolicy(current)
	if err != nil {
		return "", err
	}
	path, err := writeTLDPolicyArtifact(content)
	if err != nil {
		return "", fmt.Errorf("TLD DENY Zone 产物写入失败: %w", err)
	}
	if err := validateTLDPolicy(ctx, path); err != nil {
		return "", err
	}
	if err := runTLDNSUpdateFunc(ctx, current, previous); err != nil {
		return "", fmt.Errorf("TLD DENY 发布结果不确定，需人工核对 Primary/Secondary: %w", err)
	}
	serial, err := queryTLDPolicySerial(ctx)
	if err != nil {
		return "", fmt.Errorf("TLD DENY 更新后状态不确定，需人工核对 Primary/Secondary: %w", err)
	}
	return serial, nil
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
	if !tldPolicyPublishEnabled() {
		updated.PolicyStatus = "not_configured"
		updated.PolicyMessage = "未启用 TLD DENY RPZ 发布；仅同步 TLD 数据"
	} else if tldPolicyZone() == "" {
		updated.PolicyStatus = "error"
		updated.PolicyMessage = "已启用 TLD DENY RPZ 发布，但未配置 TLD_DENY_ZONE"
	} else if previous.PolicyStatus == "reconcile_required" {
		updated.PolicyStatus = "reconcile_required"
		updated.PolicySerial = previous.PolicySerial
		updated.PolicyLastPublished = previous.PolicyLastPublished
		updated.PolicyMessage = "上次 TLD DENY 发布结果需人工核对；核对完成前禁止自动重放"
	} else if previous.PolicyStatus == "published" && tldEntriesEqual(previous.TLDs, updated.TLDs) &&
		(previous.SHA256 == updated.SHA256 || unchanged) {
		updated.PolicyStatus = previous.PolicyStatus
		updated.PolicySerial = previous.PolicySerial
		updated.PolicyLastPublished = previous.PolicyLastPublished
		updated.PolicyMessage = previous.PolicyMessage
	} else {
		if previous.PolicyStatus == "published" && len(previous.TLDs) == 0 {
			updated.PolicyStatus = "reconcile_required"
			updated.PolicyMessage = "历史 TLD 状态缺少已发布条目，禁止盲目覆盖；请先人工核对 deny RPZ"
		} else {
			updated.PolicyStatus = "pending"
			updated.PolicyMessage = "TLD 数据已保存，等待 deny RPZ 发布"
		}
	}
	if err := saveTLDState(updated); err != nil {
		failed := previous
		failed.Status = "error"
		failed.Message = "TLD 状态持久化失败：" + err.Error()
		setTLDStatus(failed)
		return err
	}
	setTLDStatus(updated)
	if updated.PolicyStatus != "pending" {
		return nil
	}
	serial, publishErr := publishTLDPolicy(ctx, updated.TLDs, previous.TLDs)
	if publishErr != nil {
		failed := updated
		failed.PolicyStatus = "reconcile_required"
		failed.PolicyMessage = publishErr.Error()
		setTLDStatus(failed)
		if persistErr := saveTLDState(failed); persistErr != nil {
			return fmt.Errorf("%w；TLD DENY 状态持久化也失败: %v", publishErr, persistErr)
		}
		return publishErr
	}
	updated.PolicyStatus = "published"
	updated.PolicySerial = serial
	updated.PolicyLastPublished = time.Now().UTC().Format(time.RFC3339)
	updated.PolicyMessage = "TLD DENY RPZ 已通过 nsupdate 发布并读取 Primary SOA Serial"
	if err := saveTLDState(updated); err != nil {
		failed := updated
		failed.PolicyStatus = "reconcile_required"
		failed.PolicyMessage = "TLD DENY 已可能更新，但发布状态持久化失败，需人工核对 Primary/Secondary"
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
