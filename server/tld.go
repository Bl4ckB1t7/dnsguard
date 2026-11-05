package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	PolicyZoneStatus    string   `json:"policyZoneStatus,omitempty"`
	PolicySecondary     string   `json:"policySecondaryStatus,omitempty"`
	PolicyRecursion     string   `json:"policyRecursionStatus,omitempty"`
	PolicyTrigger       string   `json:"policyTrigger,omitempty"`
	TLDs                []string `json:"-"`
	PublishedTLDs       []string `json:"-"`
	PendingTLDs         []string `json:"-"`
}

type tldStateFile struct {
	TLDStatus
	TLDs          []string `json:"tlds,omitempty"`
	PublishedTLDs []string `json:"publishedTlds,omitempty"`
	PendingTLDs   []string `json:"pendingTlds,omitempty"`
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

func tldPublishTimeout() time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(os.Getenv("TLD_PUBLISH_TIMEOUT_SECONDS")))
	if err != nil || seconds < 15 || seconds > 15*60 {
		seconds = 120
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
	loaded.PublishedTLDs = append([]string(nil), persisted.PublishedTLDs...)
	loaded.PendingTLDs = append([]string(nil), persisted.PendingTLDs...)
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
	content, err := json.MarshalIndent(tldStateFile{TLDStatus: status, TLDs: status.TLDs, PublishedTLDs: status.PublishedTLDs, PendingTLDs: status.PendingTLDs}, "", "  ")
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

func validateTLDCountChange(previous TLDStatus, currentCount int) error {
	previousCount := previous.TLDCount
	if previousCount == 0 {
		previousCount = len(previous.TLDs)
	}
	if previousCount <= 0 || currentCount >= previousCount {
		return nil
	}
	// A reduction of more than 10% is treated as a source anomaly. The
	// threshold is relative to the last accepted list, not a fixed TLD count.
	if currentCount*100 < previousCount*90 {
		return fmt.Errorf("TLD 列表数量异常下降: previous=%d current=%d，超过 10%%，保留上一份有效列表", previousCount, currentCount)
	}
	return nil
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
	if err := validateTLDCountChange(previous, count); err != nil {
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
	verifyTLDPolicyFunc = verifyTLDPolicy
	queryTLDEntriesFunc = queryTLDPolicyEntries
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

type tldUpdateOperation struct {
	Entry  string
	Delete bool
}

func tldPublishBatchTLDs() int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv("TLD_PUBLISH_BATCH_TLDS")))
	if err != nil || value < 1 || value > 500 {
		return 100
	}
	return value
}

func tldPublishBatchBytes() int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv("TLD_PUBLISH_BATCH_BYTES")))
	if err != nil || value < 4096 || value > 64*1024 {
		return 32 * 1024
	}
	return value
}

func tldSetDiff(current, previous []string) (adds, removes []string, err error) {
	normalizedCurrent, err := normalizeTLDEntries(current)
	if err != nil {
		return nil, nil, err
	}
	normalizedPrevious := []string{}
	if len(previous) > 0 {
		normalizedPrevious, err = normalizeTLDEntries(previous)
		if err != nil {
			return nil, nil, err
		}
	}
	currentSet := make(map[string]struct{}, len(normalizedCurrent))
	previousSet := make(map[string]struct{}, len(normalizedPrevious))
	for _, entry := range normalizedPrevious {
		previousSet[entry] = struct{}{}
	}
	for _, entry := range normalizedCurrent {
		currentSet[entry] = struct{}{}
		if _, exists := previousSet[entry]; !exists {
			adds = append(adds, entry)
		}
	}
	for _, entry := range normalizedPrevious {
		if _, exists := currentSet[entry]; !exists {
			removes = append(removes, entry)
		}
	}
	// The normalized input is sorted, so sorting the result keeps batch
	// contents deterministic and makes audit/reproduction easier.
	sort.Strings(adds)
	sort.Strings(removes)
	return adds, removes, nil
}

func tldUpdateLines(operation tldUpdateOperation) []string {
	label := strings.ToLower(operation.Entry)
	zone := tldPolicyZone()
	if operation.Delete {
		return []string{
			fmt.Sprintf("update delete %s.%s. CNAME\n", label, zone),
			fmt.Sprintf("update delete *.%s.%s. CNAME\n", label, zone),
		}
	}
	return []string{
		fmt.Sprintf("update add %s.%s. %d CNAME .\n", label, zone, tldPolicyTTL()),
		fmt.Sprintf("update add *.%s.%s. %d CNAME .\n", label, zone, tldPolicyTTL()),
	}
}

func buildTLDUpdateBatches(adds, removes []string) [][]tldUpdateOperation {
	operations := make([]tldUpdateOperation, 0, len(adds)+len(removes))
	for _, entry := range removes {
		operations = append(operations, tldUpdateOperation{Entry: entry, Delete: true})
	}
	for _, entry := range adds {
		operations = append(operations, tldUpdateOperation{Entry: entry})
	}
	maxTLDs := tldPublishBatchTLDs()
	maxBytes := tldPublishBatchBytes()
	headerBytes := len(fmt.Sprintf("server %s %s\nzone %s\n", rpzConfig("RPZ_PRIMARY", ""), rpzConfig("RPZ_PRIMARY_PORT", "53"), tldPolicyZone()))
	batches := make([][]tldUpdateOperation, 0)
	current := make([]tldUpdateOperation, 0, maxTLDs)
	currentBytes := headerBytes + len("send\n")
	for _, operation := range operations {
		lines := tldUpdateLines(operation)
		operationBytes := len(lines[0]) + len(lines[1])
		if len(current) > 0 && (len(current) >= maxTLDs || currentBytes+operationBytes > maxBytes) {
			batches = append(batches, current)
			current = make([]tldUpdateOperation, 0, maxTLDs)
			currentBytes = headerBytes + len("send\n")
		}
		current = append(current, operation)
		currentBytes += operationBytes
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}

func runTLDNSUpdate(ctx context.Context, current, previous []string) error {
	adds, removes, err := tldSetDiff(current, previous)
	if err != nil {
		return err
	}
	if len(adds) == 0 && len(removes) == 0 {
		return nil
	}
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
	batches := buildTLDUpdateBatches(adds, removes)
	for index, batch := range batches {
		var input strings.Builder
		fmt.Fprintf(&input, "server %s %s\nzone %s\n", server, port, zone)
		for _, operation := range batch {
			for _, line := range tldUpdateLines(operation) {
				input.WriteString(line)
			}
		}
		input.WriteString("send\n")
		command := exec.CommandContext(ctx, "nsupdate", "-k", keyFile) // #nosec G702 -- executable is fixed and keyFile is protected deployment configuration.
		command.Stdin = strings.NewReader(input.String())
		output, updateErr := command.CombinedOutput()
		if updateErr != nil {
			return fmt.Errorf("TLD DENY nsupdate 批次 %d/%d 失败；已完成 %d/%d 批，结果可能不确定，需人工核对: %s", index+1, len(batches), index, len(batches), strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func queryTLDPolicySerial(ctx context.Context) (string, error) {
	server := rpzConfig("RPZ_PRIMARY", "")
	port := rpzConfig("RPZ_PRIMARY_PORT", "53")
	if server == "" {
		return "", fmt.Errorf("RPZ_PRIMARY 未配置")
	}
	command := exec.CommandContext(ctx, "dig", "@"+server, "-p", port, "+norecurse", tldPolicyZone(), "SOA", "+short", "+time=2", "+tries=1")
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

func parseTLDPolicyAXFR(content, zone string) ([]string, error) {
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if !domainPattern.MatchString(zone) {
		return nil, fmt.Errorf("TLD DENY Zone 无效")
	}
	suffix := "." + zone
	presence := make(map[string]uint8)
	for _, raw := range strings.Split(content, "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 5 {
			continue
		}
		typeIndex := -1
		for index, field := range fields {
			if strings.EqualFold(field, "CNAME") {
				typeIndex = index
				break
			}
		}
		if typeIndex < 1 || typeIndex+1 >= len(fields) {
			continue
		}
		if strings.TrimSuffix(fields[typeIndex+1], ".") != "" {
			return nil, fmt.Errorf("TLD DENY Zone 存在非拒绝 CNAME: %s", strings.Join(fields, " "))
		}
		name := strings.TrimSuffix(strings.ToLower(fields[0]), ".")
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		relative := strings.TrimSuffix(strings.TrimSuffix(name, suffix), ".")
		bit := uint8(1)
		if strings.HasPrefix(relative, "*.") {
			bit = 2
			relative = strings.TrimPrefix(relative, "*.")
		}
		entry := strings.ToUpper(relative)
		if !tldLabelRE.MatchString(entry) {
			return nil, fmt.Errorf("TLD DENY Zone 存在非 TLD 触发项: %s", relative)
		}
		presence[entry] |= bit
	}
	entries := make([]string, 0, len(presence))
	for entry, bits := range presence {
		if bits != 3 {
			return nil, fmt.Errorf("TLD DENY Zone 触发项不完整: %s", entry)
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("TLD DENY Zone 未找到 CNAME . 触发项")
	}
	sort.Strings(entries)
	return entries, nil
}

func queryTLDPolicyEntries(ctx context.Context) ([]string, error) {
	server := rpzConfig("RPZ_PRIMARY", "")
	port := rpzConfig("RPZ_PRIMARY_PORT", "53")
	keyFile := strings.TrimSpace(os.Getenv("RPZ_KEY_FILE"))
	if server == "" || keyFile == "" {
		return nil, fmt.Errorf("TLD DENY AXFR 核对缺少 RPZ_PRIMARY 或 RPZ_KEY_FILE")
	}
	info, err := os.Stat(keyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("RPZ_KEY_FILE 不可安全读取")
	}
	command := exec.CommandContext(ctx, "dig", "@"+server, "-p", port, "-k", keyFile, tldPolicyZone(), "AXFR", "+tcp", "+noall", "+answer", "+time=5", "+tries=1")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("TLD DENY AXFR 核对失败: %s", strings.TrimSpace(string(output)))
	}
	return parseTLDPolicyAXFR(string(output), tldPolicyZone())
}

func verifyTLDPolicyEntries(ctx context.Context, expected []string) ([]string, error) {
	actual, err := queryTLDEntriesFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("TLD DENY Primary AXFR 全量核对失败: %w", err)
	}
	if !tldEntriesEqual(expected, actual) {
		return actual, fmt.Errorf("TLD DENY Primary AXFR 集合不一致: 目标=%d，实际=%d", len(expected), len(actual))
	}
	return actual, nil
}

type tldPolicyVerification struct {
	PrimarySerial     string
	ZoneStatus        string
	SecondaryStatus   string
	RecursionStatus   string
	Representative    string
	VerificationError string
	UpdateSent        bool
}

var tldRCodePattern = regexp.MustCompile(`status: ([A-Z]+),`)

func queryDNSRCode(ctx context.Context, address, name string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" || !dnsNodeAddressAllowed(address) {
		return "", fmt.Errorf("递归 DNS 地址为空或不在允许范围内")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = strings.Trim(address, "[]")
		port = "53"
	}
	if host == "" || strings.TrimSpace(name) == "" || !domainPattern.MatchString(strings.TrimSuffix(strings.TrimSpace(name), ".")) {
		return "", fmt.Errorf("递归检查域名无效")
	}
	command := exec.CommandContext(ctx, "dig", "@"+host, "-p", port, name, "A", "+noall", "+comments", "+time=2", "+tries=1")
	output, err := command.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("递归 DNS 查询失败: %s", strings.TrimSpace(string(output)))
	}
	match := tldRCodePattern.FindStringSubmatch(string(output))
	if len(match) != 2 {
		return "", fmt.Errorf("递归 DNS 响应缺少 RCODE")
	}
	return match[1], nil
}

func verifyTLDPolicyOnce(ctx context.Context, entries []string) (tldPolicyVerification, error) {
	normalized, err := normalizeTLDEntries(entries)
	if err != nil {
		return tldPolicyVerification{ZoneStatus: "verification_failed"}, err
	}
	domain := strings.ToLower(normalized[0]) + "." + tldPolicyZone() + "."
	verification := tldPolicyVerification{
		ZoneStatus:      "checking",
		SecondaryStatus: "not_configured",
		RecursionStatus: "not_configured",
		Representative:  domain,
	}
	dnsMu.RLock()
	nodes := append([]DNSNode(nil), state.Nodes...)
	dnsMu.RUnlock()
	if len(nodes) == 0 {
		verification.ZoneStatus = "verification_failed"
		verification.VerificationError = "未配置 DNS 节点"
		return verification, fmt.Errorf("TLD DENY 发布后未配置 DNS 节点，无法完成验收")
	}
	primarySerial := ""
	secondaryConfigured := false
	secondarySynced := true
	serials := make(map[string]string, len(nodes))
	secondaryNodes := make([]DNSNode, 0, len(nodes))
	var failures []string
	for _, node := range nodes {
		role, _ := dnsNodeRoleKind(node.Role)
		serial, probeErr := probeDNSZone(ctx, node.Address, tldPolicyZone())
		if role == "primary" || node.ID == "primary-1" {
			if probeErr != nil {
				failures = append(failures, fmt.Sprintf("Primary %s: %v", node.Name, probeErr))
			} else {
				primarySerial = serial
				serials[node.ID] = serial
			}
		} else {
			secondaryConfigured = true
			secondaryNodes = append(secondaryNodes, node)
			if probeErr != nil {
				secondarySynced = false
				failures = append(failures, fmt.Sprintf("Secondary %s: %v", node.Name, probeErr))
			} else {
				serials[node.ID] = serial
			}
		}
		answers, answerErr := queryDNSNode(ctx, node.Address, domain, "CNAME")
		if answerErr != nil || len(answers) == 0 || !containsDNSAnswer(answers, ".") {
			if answerErr != nil {
				failures = append(failures, fmt.Sprintf("节点 %s 代表性 TLD 触发项查询失败: %v", node.Name, answerErr))
			} else {
				failures = append(failures, fmt.Sprintf("节点 %s 代表性 TLD 触发项未返回 CNAME .", node.Name))
			}
		}
	}
	if primarySerial != "" {
		for _, node := range secondaryNodes {
			if serial, ok := serials[node.ID]; !ok || serial != primarySerial {
				secondarySynced = false
				if ok {
					failures = append(failures, fmt.Sprintf("Secondary %s Serial=%s，Primary=%s", node.Name, serial, primarySerial))
				}
			}
		}
		if _, axfrErr := verifyTLDPolicyEntries(ctx, normalized); axfrErr != nil {
			failures = append(failures, axfrErr.Error())
		}
	}
	if primarySerial == "" {
		verification.ZoneStatus = "verification_failed"
	} else {
		verification.PrimarySerial = primarySerial
		verification.ZoneStatus = "primary_published"
	}
	if secondaryConfigured {
		if secondarySynced && primarySerial != "" {
			verification.SecondaryStatus = "synced"
		} else {
			verification.SecondaryStatus = "sync_exception"
		}
	}
	if recursor := strings.TrimSpace(os.Getenv("TLD_DENY_RECURSOR")); recursor != "" || strings.TrimSpace(os.Getenv("TLD_DENY_CHECK_NAME")) != "" {
		checkName := strings.TrimSpace(os.Getenv("TLD_DENY_CHECK_NAME"))
		if recursor == "" || checkName == "" {
			verification.RecursionStatus = "not_run"
			failures = append(failures, "TLD_DENY_RECURSOR 和 TLD_DENY_CHECK_NAME 必须同时配置")
		} else {
			rcode, rcodeErr := queryDNSRCode(ctx, recursor, checkName)
			expected := strings.ToUpper(strings.TrimSpace(os.Getenv("TLD_DENY_EXPECTED_RCODE")))
			if expected == "" {
				expected = "NXDOMAIN"
			}
			if rcodeErr != nil {
				verification.RecursionStatus = "failed"
				failures = append(failures, rcodeErr.Error())
			} else if rcode != expected {
				verification.RecursionStatus = "failed"
				failures = append(failures, fmt.Sprintf("递归策略 RCODE=%s，期望=%s", rcode, expected))
			} else {
				verification.RecursionStatus = "verified"
			}
		}
	}
	if len(failures) > 0 {
		verification.VerificationError = strings.Join(failures, "; ")
		return verification, fmt.Errorf("TLD DENY 发布验收失败: %s", verification.VerificationError)
	}
	verification.ZoneStatus = "published"
	return verification, nil
}

func verifyTLDPolicy(ctx context.Context, entries []string) (tldPolicyVerification, error) {
	var lastVerification tldPolicyVerification
	var lastErr error
	for {
		lastVerification, lastErr = verifyTLDPolicyOnce(ctx, entries)
		if lastErr == nil {
			return lastVerification, nil
		}
		// A configured recursive check is an explicit assertion. Do not hide a
		// failed assertion behind a retry loop; only BIND propagation is retried.
		if lastVerification.RecursionStatus == "failed" || lastVerification.RecursionStatus == "not_run" {
			return lastVerification, lastErr
		}
		if strings.Contains(lastErr.Error(), "未配置 DNS 节点") {
			return lastVerification, lastErr
		}
		select {
		case <-ctx.Done():
			return lastVerification, fmt.Errorf("TLD DENY Secondary/触发项验收超时: %w; last=%v", ctx.Err(), lastErr)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func containsDNSAnswer(answers []string, expected string) bool {
	for _, answer := range answers {
		if strings.TrimSuffix(strings.TrimSpace(answer), ".") == strings.TrimSuffix(expected, ".") {
			return true
		}
	}
	return false
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

func publishTLDPolicy(ctx context.Context, current, previous []string, previousSerial string) (tldPolicyVerification, error) {
	content, err := compileTLDPolicy(current)
	if err != nil {
		return tldPolicyVerification{ZoneStatus: "verification_failed"}, err
	}
	path, err := writeTLDPolicyArtifact(content)
	if err != nil {
		return tldPolicyVerification{ZoneStatus: "verification_failed"}, fmt.Errorf("TLD DENY Zone 产物写入失败: %w", err)
	}
	if err := validateTLDPolicy(ctx, path); err != nil {
		return tldPolicyVerification{ZoneStatus: "verification_failed"}, err
	}
	if err := runTLDNSUpdateFunc(ctx, current, previous); err != nil {
		return tldPolicyVerification{ZoneStatus: "reconcile_required"}, fmt.Errorf("TLD DENY 发布结果不确定，需人工核对 Primary/Secondary: %w", err)
	}
	serial, err := queryTLDPolicySerial(ctx)
	if err != nil {
		return tldPolicyVerification{ZoneStatus: "reconcile_required"}, fmt.Errorf("TLD DENY 更新后状态不确定，需人工核对 Primary/Secondary: %w", err)
	}
	if previousSerial != "" && serial == previousSerial {
		return tldPolicyVerification{PrimarySerial: serial, ZoneStatus: "reconcile_required"}, fmt.Errorf("TLD DENY Primary SOA Serial 未变化，发布结果需人工核对")
	}
	verification, verifyErr := verifyTLDPolicyFunc(ctx, current)
	verification.UpdateSent = true
	verification.PrimarySerial = serial
	if verifyErr != nil {
		return verification, verifyErr
	}
	verification.ZoneStatus = "published"
	return verification, nil
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
	updated, _, err := fetchTLDDocument(ctx, tldSourceURL(), previous)
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
	updated.PublishedTLDs = append([]string(nil), previous.PublishedTLDs...)
	updated.PendingTLDs = append([]string(nil), previous.PendingTLDs...)
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
	} else if previous.PolicyStatus == "pending_verification" && len(previous.PendingTLDs) > 0 {
		updated.PolicyStatus = "pending_verification"
		updated.PolicySerial = previous.PolicySerial
		updated.PolicyLastPublished = previous.PolicyLastPublished
		updated.PolicyMessage = "上次 TLD DENY 已发送到 Primary，当前只复核待确认目标，不重复执行 nsupdate"
	} else if previous.PolicyStatus == "pending" {
		updated.PolicyStatus = "reconcile_required"
		updated.PolicySerial = previous.PolicySerial
		updated.PolicyLastPublished = previous.PolicyLastPublished
		updated.PolicyMessage = "检测到上次 TLD DENY 发布停留在 pending；禁止自动重放，请先人工核对 Primary/Secondary"
	} else if previous.PolicyStatus == "published" && len(previous.PublishedTLDs) > 0 && tldEntriesEqual(previous.PublishedTLDs, updated.TLDs) {
		updated.PolicyStatus = previous.PolicyStatus
		updated.PolicySerial = previous.PolicySerial
		updated.PolicyLastPublished = previous.PolicyLastPublished
		updated.PolicyMessage = previous.PolicyMessage
		updated.PolicyZoneStatus = previous.PolicyZoneStatus
		updated.PolicySecondary = previous.PolicySecondary
		updated.PolicyRecursion = previous.PolicyRecursion
		updated.PolicyTrigger = previous.PolicyTrigger
	} else if previous.PolicyStatus == "sync_exception" && len(previous.PendingTLDs) > 0 {
		updated.PolicyStatus = "pending_verification"
		updated.PolicySerial = previous.PolicySerial
		updated.PolicyLastPublished = previous.PolicyLastPublished
		updated.PolicyMessage = "TLD DENY 已发送到 Primary，先重新核对 Zone、Secondary 和代表性触发项，不重复执行 nsupdate"
		updated.PolicyZoneStatus = previous.PolicyZoneStatus
		updated.PolicySecondary = previous.PolicySecondary
		updated.PolicyRecursion = previous.PolicyRecursion
		updated.PolicyTrigger = previous.PolicyTrigger
	} else if previous.PolicyStatus == "sync_exception" && len(previous.TLDs) > 0 {
		// Compatibility with states written before PendingTLDs existed: the
		// last downloaded list is treated only as a verification target, never
		// as permission to replay an uncertain update.
		updated.PolicyStatus = "pending_verification"
		updated.PendingTLDs = append([]string(nil), previous.TLDs...)
		updated.PolicySerial = previous.PolicySerial
		updated.PolicyLastPublished = previous.PolicyLastPublished
		updated.PolicyMessage = "检测到历史 sync_exception，使用旧待确认快照复核，禁止自动重放"
		updated.PolicyZoneStatus = previous.PolicyZoneStatus
		updated.PolicySecondary = previous.PolicySecondary
		updated.PolicyRecursion = previous.PolicyRecursion
		updated.PolicyTrigger = previous.PolicyTrigger
	} else if previous.PolicyStatus == "pending_verification" {
		updated.PolicyStatus = "reconcile_required"
		updated.PolicyMessage = "pending_verification 缺少待确认快照，禁止自动重放，请先人工核对"
	} else {
		if previous.PolicyStatus == "published" && len(previous.PublishedTLDs) == 0 {
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
	if updated.PolicyStatus == "pending_verification" {
		verificationTarget := append([]string(nil), updated.PendingTLDs...)
		if len(verificationTarget) == 0 {
			updated.PolicyStatus = "reconcile_required"
			updated.PolicyMessage = "待验证 TLD 快照为空，禁止自动重放，请先人工核对"
			setTLDStatus(updated)
			if persistErr := saveTLDState(updated); persistErr != nil {
				return persistErr
			}
			return fmt.Errorf("TLD DENY 待验证快照为空")
		}
		publishCtx, cancel := context.WithTimeout(ctx, tldPublishTimeout())
		verification, verifyErr := verifyTLDPolicyFunc(publishCtx, verificationTarget)
		cancel()
		updated.PolicySerial = verification.PrimarySerial
		updated.PolicyZoneStatus = verification.ZoneStatus
		updated.PolicySecondary = verification.SecondaryStatus
		updated.PolicyRecursion = verification.RecursionStatus
		updated.PolicyTrigger = verification.Representative
		if verifyErr != nil {
			updated.PolicyStatus = "pending_verification"
			updated.PolicyMessage = verifyErr.Error()
			setTLDStatus(updated)
			if persistErr := saveTLDState(updated); persistErr != nil {
				return fmt.Errorf("%w；TLD DENY 复核状态持久化失败: %v", verifyErr, persistErr)
			}
			return verifyErr
		}
		updated.PolicyStatus = "published"
		updated.PublishedTLDs = verificationTarget
		updated.PendingTLDs = nil
		updated.PolicyMessage = "TLD DENY 待确认目标已通过 Primary、Secondary 和代表性触发项复核；递归检查按配置执行"
		updated.PolicyLastPublished = time.Now().UTC().Format(time.RFC3339)
		if err := saveTLDState(updated); err != nil {
			return err
		}
		setTLDStatus(updated)
		return nil
	}
	if updated.PolicyStatus != "pending" {
		return nil
	}
	publishCtx, cancel := context.WithTimeout(ctx, tldPublishTimeout())
	verification, publishErr := publishTLDPolicy(publishCtx, updated.TLDs, previous.PublishedTLDs, previous.PolicySerial)
	cancel()
	if publishErr != nil {
		failed := updated
		if verification.UpdateSent {
			failed.PolicyStatus = "pending_verification"
			failed.PendingTLDs = append([]string(nil), updated.TLDs...)
		} else if verification.ZoneStatus == "reconcile_required" {
			failed.PolicyStatus = "reconcile_required"
		} else {
			failed.PolicyStatus = "error"
		}
		failed.PolicySerial = verification.PrimarySerial
		failed.PolicyZoneStatus = verification.ZoneStatus
		failed.PolicySecondary = verification.SecondaryStatus
		failed.PolicyRecursion = verification.RecursionStatus
		failed.PolicyTrigger = verification.Representative
		failed.PolicyMessage = publishErr.Error()
		setTLDStatus(failed)
		if persistErr := saveTLDState(failed); persistErr != nil {
			return fmt.Errorf("%w；TLD DENY 状态持久化也失败: %v", publishErr, persistErr)
		}
		return publishErr
	}
	updated.PolicyStatus = "published"
	updated.PolicySerial = verification.PrimarySerial
	updated.PolicyLastPublished = time.Now().UTC().Format(time.RFC3339)
	updated.PolicyZoneStatus = verification.ZoneStatus
	updated.PolicySecondary = verification.SecondaryStatus
	updated.PolicyRecursion = verification.RecursionStatus
	updated.PolicyTrigger = verification.Representative
	updated.PublishedTLDs = append([]string(nil), updated.TLDs...)
	updated.PendingTLDs = nil
	updated.PolicyMessage = "TLD DENY RPZ 已通过 Primary、Secondary 和代表性触发项验收；递归检查按配置执行"
	if err := saveTLDState(updated); err != nil {
		failed := updated
		failed.PolicyStatus = "reconcile_required"
		failed.PublishedTLDs = append([]string(nil), previous.PublishedTLDs...)
		failed.PendingTLDs = append([]string(nil), updated.TLDs...)
		failed.PolicyMessage = "TLD DENY 已可能更新，但发布状态持久化失败，需人工核对 Primary/Secondary"
		setTLDStatus(failed)
		return err
	}
	setTLDStatus(updated)
	return nil
}

func reconcileTLDPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	tldSyncMu.Lock()
	defer tldSyncMu.Unlock()
	current := tldStatusSnapshot()
	if current.PolicyStatus != "reconcile_required" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "当前没有需要人工核对的 TLD DENY 发布任务"})
		return
	}
	if len(current.TLDs) == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "当前 TLD 列表为空，不能恢复发布"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), tldPublishTimeout())
	defer cancel()
	actual, err := verifyTLDPolicyEntries(ctx, current.TLDs)
	if err != nil {
		current.PolicyMessage = "人工核对失败，未改变 reconcile_required 状态: " + err.Error()
		setTLDStatus(current)
		_ = saveTLDState(current)
		writeJSON(w, http.StatusConflict, map[string]string{"error": current.PolicyMessage})
		return
	}
	verification, verifyErr := verifyTLDPolicyFunc(ctx, current.TLDs)
	if verifyErr != nil {
		current.PolicyMessage = "人工核对的 Zone 内容一致，但节点或递归验收未通过: " + verifyErr.Error()
		current.PolicySerial = verification.PrimarySerial
		current.PolicyZoneStatus = verification.ZoneStatus
		current.PolicySecondary = verification.SecondaryStatus
		current.PolicyRecursion = verification.RecursionStatus
		current.PolicyTrigger = verification.Representative
		setTLDStatus(current)
		if persistErr := saveTLDState(current); persistErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": persistErr.Error()})
			return
		}
		writeJSON(w, http.StatusConflict, map[string]string{"error": current.PolicyMessage})
		return
	}
	current.PolicyStatus = "published"
	current.PublishedTLDs = append([]string(nil), current.TLDs...)
	current.PendingTLDs = nil
	current.PolicySerial = verification.PrimarySerial
	current.PolicyZoneStatus = verification.ZoneStatus
	current.PolicySecondary = verification.SecondaryStatus
	current.PolicyRecursion = verification.RecursionStatus
	current.PolicyTrigger = verification.Representative
	current.PolicyLastPublished = time.Now().UTC().Format(time.RFC3339)
	current.PolicyMessage = "管理员已核对 AXFR、Primary、Secondary 和代表性触发项，TLD DENY 自动发布已恢复"
	if err := saveTLDState(current); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "恢复状态保存失败，仍需人工核对: " + err.Error()})
		return
	}
	setTLDStatus(current)
	if err := recordCriticalAudit(r, authUsername(), "tld.policy.reconcile", fmt.Sprintf("success: %d TLDs, serial=%s", len(actual), verification.PrimarySerial)); err != nil {
		current.PolicyStatus = "reconcile_required"
		current.PolicyMessage = "恢复后审计记录失败，已重新锁定人工核对: " + err.Error()
		setTLDStatus(current)
		_ = saveTLDState(current)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": current.PolicyMessage})
		return
	}
	writeJSON(w, http.StatusOK, current)
}

func startTLDSyncMonitor() {
	if !tldSyncEnabled() {
		return
	}
	go func() {
		_ = syncTLDNow(context.Background())
		ticker := time.NewTicker(tldSyncInterval())
		defer ticker.Stop()
		for range ticker.C {
			_ = syncTLDNow(context.Background())
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
