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

type tldPolicyVerification struct {
	PrimarySerial     string
	ZoneStatus        string
	SecondaryStatus   string
	RecursionStatus   string
	Representative    string
	VerificationError string
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
		updated.PolicyZoneStatus = previous.PolicyZoneStatus
		updated.PolicySecondary = previous.PolicySecondary
		updated.PolicyRecursion = previous.PolicyRecursion
		updated.PolicyTrigger = previous.PolicyTrigger
	} else if (previous.PolicyStatus == "sync_exception" || previous.PolicyStatus == "pending_verification") && tldEntriesEqual(previous.TLDs, updated.TLDs) {
		updated.PolicyStatus = "pending_verification"
		updated.PolicySerial = previous.PolicySerial
		updated.PolicyLastPublished = previous.PolicyLastPublished
		updated.PolicyMessage = "TLD DENY 已有发布记录，先重新核对 Zone、Secondary 和代表性触发项，不重复执行 nsupdate"
		updated.PolicyZoneStatus = previous.PolicyZoneStatus
		updated.PolicySecondary = previous.PolicySecondary
		updated.PolicyRecursion = previous.PolicyRecursion
		updated.PolicyTrigger = previous.PolicyTrigger
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
	if updated.PolicyStatus == "pending_verification" {
		publishCtx, cancel := context.WithTimeout(ctx, tldPublishTimeout())
		verification, verifyErr := verifyTLDPolicyFunc(publishCtx, updated.TLDs)
		cancel()
		updated.PolicySerial = verification.PrimarySerial
		updated.PolicyZoneStatus = verification.ZoneStatus
		updated.PolicySecondary = verification.SecondaryStatus
		updated.PolicyRecursion = verification.RecursionStatus
		updated.PolicyTrigger = verification.Representative
		if verifyErr != nil {
			updated.PolicyStatus = "sync_exception"
			updated.PolicyMessage = verifyErr.Error()
			setTLDStatus(updated)
			if persistErr := saveTLDState(updated); persistErr != nil {
				return fmt.Errorf("%w；TLD DENY 复核状态持久化失败: %v", verifyErr, persistErr)
			}
			return verifyErr
		}
		updated.PolicyStatus = "published"
		updated.PolicyMessage = "TLD DENY 已存在于 Primary，Secondary 和代表性触发项复核通过；递归检查按配置执行"
		updated.PolicyLastPublished = previous.PolicyLastPublished
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
	verification, publishErr := publishTLDPolicy(publishCtx, updated.TLDs, previous.TLDs, previous.PolicySerial)
	cancel()
	if publishErr != nil {
		failed := updated
		if verification.ZoneStatus == "reconcile_required" {
			failed.PolicyStatus = "reconcile_required"
		} else {
			failed.PolicyStatus = "sync_exception"
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
	updated.PolicyMessage = "TLD DENY RPZ 已通过 Primary、Secondary 和代表性触发项验收；递归检查按配置执行"
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
