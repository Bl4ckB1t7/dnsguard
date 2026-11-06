package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type rpzRuntime struct {
	Mode        string
	LastPublish string
	Message     string
	JobID       string
	JobStatus   string
}

type PublishJob struct {
	ID         string         `json:"id"`
	Status     string         `json:"status"`
	SyncStatus string         `json:"syncStatus,omitempty"`
	Message    string         `json:"message,omitempty"`
	Validation string         `json:"validation,omitempty"`
	Error      string         `json:"error,omitempty"`
	CreatedAt  string         `json:"createdAt"`
	StartedAt  string         `json:"startedAt,omitempty"`
	FinishedAt string         `json:"finishedAt,omitempty"`
	Attempts   int            `json:"attempts,omitempty"`
	NodeChecks []RPZNodeCheck `json:"nodeChecks,omitempty"`
}

type RPZNodeCheck struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Role    string `json:"role"`
	Address string `json:"address"`
	Serial  string `json:"serial,omitempty"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}

var rpzRuntimeMu sync.RWMutex
var rpzRuntimeState = rpzRuntime{Mode: "artifact", Message: "尚未发布", JobStatus: "idle"}
var publishJobMu sync.RWMutex
var publishJobs = map[string]PublishJob{}
var publishJobPersistMu sync.Mutex
var publishExecutionMu sync.Mutex
var activePublishID string
var rpzSerialMu sync.Mutex
var lastRPZSerial int64
var rpzSerialPattern = regexp.MustCompile(`SOA[^\(]*\(\s*([0-9]+)`)

func rpzConfig(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func rpzStatusSnapshot() rpzRuntime {
	rpzRuntimeMu.RLock()
	defer rpzRuntimeMu.RUnlock()
	return rpzRuntimeState
}

func publishJobsPath() string {
	if path := strings.TrimSpace(os.Getenv("RPZ_PUBLISH_JOBS_FILE")); path != "" {
		return path
	}
	return dnsStatePath() + ".jobs.json"
}

func persistPublishJobs() error {
	publishJobPersistMu.Lock()
	defer publishJobPersistMu.Unlock()
	return persistPublishJobsLocked()
}

func persistPublishJobsLocked() error {
	path := publishJobsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	publishJobMu.RLock()
	jobs := make([]PublishJob, 0, len(publishJobs))
	for _, job := range publishJobs {
		jobs = append(jobs, job)
	}
	publishJobMu.RUnlock()
	content, err := json.MarshalIndent(jobs, "", "  ")
	if err != nil {
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
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
		return syncParentDir(path)
	})
}

func loadPublishJobs() error {
	content, err := os.ReadFile(publishJobsPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取 RPZ 发布任务失败: %w", err)
	}
	var jobs []PublishJob
	if err := json.Unmarshal(content, &jobs); err != nil {
		return fmt.Errorf("RPZ 发布任务文件损坏: %w", err)
	}
	recovered := false
	now := time.Now().UTC().Format(time.RFC3339)
	latestRecovered := PublishJob{}
	publishJobMu.Lock()
	publishJobs = make(map[string]PublishJob, len(jobs))
	for _, job := range jobs {
		if job.Status == "queued" || job.Status == "running" {
			job.Status = "reconcile_required"
			job.Error = "DNSGuard 重启时任务未完成，必须核对 Primary/Secondary 实际状态后再处理"
			job.FinishedAt = now
			recovered = true
			if latestRecovered.ID == "" || job.CreatedAt > latestRecovered.CreatedAt {
				latestRecovered = job
			}
		}
		publishJobs[job.ID] = job
	}
	publishJobMu.Unlock()
	if recovered {
		if err := persistPublishJobs(); err != nil {
			return fmt.Errorf("保存恢复后的 RPZ 发布任务失败: %w", err)
		}
		rpzRuntimeMu.Lock()
		rpzRuntimeState.JobID = latestRecovered.ID
		rpzRuntimeState.JobStatus = "reconcile_required"
		rpzRuntimeState.Message = "存在 DNSGuard 重启前未完成的 RPZ 发布任务，请先核对节点状态"
		rpzRuntimeMu.Unlock()
	}
	return nil
}

func updatePublishJob(id string, update func(*PublishJob)) (PublishJob, error) {
	publishJobPersistMu.Lock()
	defer publishJobPersistMu.Unlock()
	publishJobMu.Lock()
	_, exists := publishJobs[id]
	if !exists {
		publishJobMu.Unlock()
		return PublishJob{}, fmt.Errorf("RPZ 发布任务不存在: %s", id)
	}
	job := publishJobs[id]
	update(&job)
	publishJobs[id] = job
	publishJobMu.Unlock()
	if err := persistPublishJobsLocked(); err == nil {
		return job, nil
	} else {
		persistErr := fmt.Errorf("RPZ 发布任务状态持久化失败: %w", err)
		publishJobMu.Lock()
		job = publishJobs[id]
		job.Status = "reconcile_required"
		job.SyncStatus = "reconcile_required"
		job.Error = persistErr.Error() + "；禁止自动重放，必须人工核对 Primary/Secondary 实际状态"
		if job.FinishedAt == "" {
			job.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		}
		publishJobs[id] = job
		publishJobMu.Unlock()
		if recoveryErr := persistPublishJobsLocked(); recoveryErr != nil {
			log.Printf("persist RPZ publish job %s recovery state failed: %v", id, recoveryErr)
			return job, fmt.Errorf("%w；写入人工核对状态也失败: %v", persistErr, recoveryErr)
		}
		return job, persistErr
	}
}

func latestPublishJob() (PublishJob, bool) {
	publishJobMu.RLock()
	defer publishJobMu.RUnlock()
	var latest PublishJob
	for _, job := range publishJobs {
		if latest.ID == "" || job.CreatedAt > latest.CreatedAt || (job.CreatedAt == latest.CreatedAt && job.ID > latest.ID) {
			latest = job
		}
	}
	return latest, latest.ID != ""
}

func publishJobHasVerifiedCluster(job PublishJob, nodes []DNSNode) bool {
	if job.Status != "succeeded" || job.SyncStatus != "published" || len(nodes) == 0 || len(job.NodeChecks) != len(nodes) {
		return false
	}
	checks := make(map[string]RPZNodeCheck, len(job.NodeChecks))
	for _, check := range job.NodeChecks {
		if check.ID == "" || check.Status != "verified" {
			return false
		}
		if _, exists := checks[check.ID]; exists {
			return false
		}
		checks[check.ID] = check
	}
	for _, node := range nodes {
		check, ok := checks[node.ID]
		if !ok || check.Address != node.Address || check.Role != node.Role {
			return false
		}
	}
	return true
}

func getPublishJob(id string) (PublishJob, bool) {
	publishJobMu.RLock()
	job, ok := publishJobs[id]
	publishJobMu.RUnlock()
	return job, ok
}

func pendingReconciliationJob() (PublishJob, bool) {
	publishJobMu.RLock()
	defer publishJobMu.RUnlock()
	for _, job := range publishJobs {
		if job.Status == "reconcile_required" {
			return job, true
		}
	}
	return PublishJob{}, false
}

func activePublishJob() string {
	publishExecutionMu.Lock()
	defer publishExecutionMu.Unlock()
	return activePublishID
}

func reservePublishJob(id string) bool {
	publishExecutionMu.Lock()
	defer publishExecutionMu.Unlock()
	if activePublishID != "" {
		return false
	}
	activePublishID = id
	return true
}

func releasePublishJob(id string) {
	publishExecutionMu.Lock()
	if activePublishID == id {
		activePublishID = ""
	}
	publishExecutionMu.Unlock()
}

// handoffPublishJob atomically transfers a reservation held by a rollback
// operation to the publish job created from that rollback. This closes the
// check/mutate/enqueue gap without holding a lock during dig or nsupdate.
func handoffPublishJob(from, to string) bool {
	publishExecutionMu.Lock()
	defer publishExecutionMu.Unlock()
	if activePublishID != from {
		return false
	}
	activePublishID = to
	return true
}

func rpzZoneName() string {
	return rpzConfig("RPZ_ZONE", "rpz.local")
}

func rpzPrimaryEndpoint() (string, string) {
	configured := strings.TrimSpace(os.Getenv("RPZ_PRIMARY"))
	if configured == "" || strings.Contains(configured, "DNS_PRIMARY") {
		dnsMu.RLock()
		for _, node := range state.Nodes {
			role, _ := dnsNodeRoleKind(node.Role)
			if role == "primary" || node.ID == "primary-1" {
				configured = strings.TrimSpace(node.Address)
				break
			}
		}
		dnsMu.RUnlock()
	}
	if host, port, err := net.SplitHostPort(configured); err == nil {
		return strings.Trim(host, "[]"), port
	}
	return strings.Trim(configured, "[]"), rpzConfig("RPZ_PRIMARY_PORT", "53")
}

func rpzQNAMETriggers(domain string) []string {
	return []string{domain, "*." + domain}
}

func nextRPZSerial() int64 {
	rpzSerialMu.Lock()
	defer rpzSerialMu.Unlock()
	serial := time.Now().UTC().Unix()
	path := rpzConfig("RPZ_ARTIFACT_FILE", filepath.Join("data", "rpz", rpzZoneName()+".db"))
	if content, err := os.ReadFile(path); err == nil {
		if match := rpzSerialPattern.FindSubmatch(content); len(match) == 2 {
			if previous, parseErr := strconv.ParseInt(string(match[1]), 10, 64); parseErr == nil && previous >= serial {
				serial = previous + 1
			}
		}
	}
	if serial <= lastRPZSerial {
		serial = lastRPZSerial + 1
	}
	lastRPZSerial = serial
	return serial
}

func compileRPZ(rules []RPZRule) (string, error) {
	serial := nextRPZSerial()
	zone := rpzZoneName()
	var builder strings.Builder
	fmt.Fprintf(&builder, "$TTL 60\n$ORIGIN %s.\n@ SOA localhost. hostmaster.localhost. (%d 1h 15m 30d 60)\n  NS localhost.\n\n", zone, serial)
	for _, rule := range rules {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.Domain), "."))
		if !domainPattern.MatchString(domain) {
			return "", fmt.Errorf("invalid RPZ domain: %s", rule.Domain)
		}
		recordType := rpzRuleType(rule)
		recordValue := "rpz-passthru."
		if recordType == "A" {
			ip := net.ParseIP(strings.TrimSpace(rule.Value))
			if ip == nil || ip.To4() == nil {
				return "", fmt.Errorf("invalid A record address for %s: %s", rule.Domain, rule.Value)
			}
			recordValue = ip.To4().String()
			recordType = "A"
		} else {
			recordType = "CNAME"
		}
		for _, trigger := range rpzQNAMETriggers(domain) {
			fmt.Fprintf(&builder, "%s.%s. 60 %s %s ; %s\n", trigger, zone, recordType, recordValue, strings.ReplaceAll(rule.Reason, "\n", " "))
		}
	}
	return builder.String(), nil
}

func writeRPZArtifact(content string) (string, error) {
	path := rpzConfig("RPZ_ARTIFACT_FILE", filepath.Join("data", "rpz", rpzZoneName()+".db"))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o640); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	if err := syncParentDir(path); err != nil {
		return "", err
	}
	return path, nil
}

func validateRPZ(ctx context.Context, path string) string {
	checker, err := exec.LookPath("named-checkzone")
	if err != nil {
		return "named-checkzone 未安装，已完成内置规则校验"
	}
	command := exec.CommandContext(ctx, checker, rpzZoneName(), path)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("named-checkzone 失败: %s", strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output))
}

func queryDNSNode(ctx context.Context, address, name, recordType string) ([]string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, fmt.Errorf("DNS 节点地址为空")
	}
	if !dnsNodeAddressAllowed(address) {
		return nil, fmt.Errorf("DNS 节点地址不在允许范围内")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = strings.Trim(address, "[]")
		port = "53"
	}
	if host == "" || strings.TrimSpace(name) == "" || strings.TrimSpace(recordType) == "" {
		return nil, fmt.Errorf("DNS 查询参数无效")
	}
	// Rule verification reads records from the RPZ zone itself. It must be an
	// authoritative, non-recursive query; recursive policy evaluation is tested
	// separately and must not be used as publication evidence.
	command := exec.CommandContext(ctx, "dig", "@"+host, "-p", port, "+norecurse", name, recordType, "+short", "+time=2", "+tries=1")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("dig 失败: %s", strings.TrimSpace(string(output)))
	}
	lines := strings.Fields(string(output))
	return lines, nil
}

func verifyRPZRuleAnswer(ctx context.Context, node DNSNode, rule RPZRule) error {
	recordType := rpzRuleType(rule)
	expected := "rpz-passthru."
	if recordType == "A" {
		expected = strings.TrimSpace(rule.Value)
	}
	for _, trigger := range rpzQNAMETriggers(rule.Domain) {
		name := trigger + "." + rpzZoneName() + "."
		answers, err := queryDNSNode(ctx, node.Address, name, recordType)
		if err != nil {
			return fmt.Errorf("节点 %s 规则 %s 查询失败: %w", node.Name, name, err)
		}
		matched := false
		for _, answer := range answers {
			if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(answer), "."), strings.TrimSuffix(expected, ".")) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("节点 %s 规则 %s 返回 %q，期望 %q", node.Name, name, strings.Join(answers, " "), expected)
		}
	}
	return nil
}

func verifyRPZRuleRemoved(ctx context.Context, node DNSNode, rule RPZRule) error {
	for _, trigger := range rpzQNAMETriggers(rule.Domain) {
		name := trigger + "." + rpzZoneName() + "."
		answers, err := queryDNSNode(ctx, node.Address, name, rpzRuleType(rule))
		if err != nil {
			return fmt.Errorf("节点 %s 删除规则 %s 查询失败: %w", node.Name, name, err)
		}
		if len(answers) > 0 {
			return fmt.Errorf("节点 %s 删除规则 %s 仍返回 %q", node.Name, name, strings.Join(answers, " "))
		}
	}
	return nil
}

func verifyRPZClusterOnce(ctx context.Context, previousSerial int64, rules, removed []RPZRule) ([]RPZNodeCheck, error) {
	dnsMu.RLock()
	nodes := append([]DNSNode(nil), state.Nodes...)
	dnsMu.RUnlock()
	if len(nodes) == 0 {
		return nil, fmt.Errorf("未配置 DNS 节点")
	}
	checks := make([]RPZNodeCheck, len(nodes))
	primarySerial := int64(-1)
	serials := make(map[string]int64, len(nodes))
	checkIndexes := make(map[string]int, len(nodes))
	var failures []string
	for index, node := range nodes {
		checks[index] = RPZNodeCheck{ID: node.ID, Name: node.Name, Role: node.Role, Address: node.Address, Status: "checking"}
		checkIndexes[node.ID] = index
		serialText, err := probeDNSNode(ctx, node.Address)
		if err != nil {
			checks[index].Status = "unreachable"
			checks[index].Error = err.Error()
			failures = append(failures, fmt.Sprintf("%s(%s): %v", node.Name, node.Address, err))
			continue
		}
		serial, err := strconv.ParseInt(serialText, 10, 64)
		if err != nil {
			checks[index].Status = "invalid"
			checks[index].Error = err.Error()
			failures = append(failures, fmt.Sprintf("%s(%s): Serial 无效 %s", node.Name, node.Address, serialText))
			continue
		}
		checks[index].Serial = serialText
		checks[index].Status = "healthy"
		serials[node.ID] = serial
		if role, _ := dnsNodeRoleKind(node.Role); role == "primary" || node.ID == "primary-1" {
			primarySerial = serial
		}
	}
	if primarySerial < 0 {
		failures = append(failures, "Primary 未能完成 SOA 探测")
	} else if primarySerial <= previousSerial {
		failures = append(failures, fmt.Sprintf("Primary SOA Serial 未严格递增: previous=%d actual=%d", previousSerial, primarySerial))
	}
	for _, node := range nodes {
		if role, _ := dnsNodeRoleKind(node.Role); role == "primary" || node.ID == "primary-1" {
			continue
		}
		if serial, ok := serials[node.ID]; !ok {
			continue
		} else if serial != primarySerial {
			checks[checkIndexes[node.ID]].Status = "sync_exception"
			checks[checkIndexes[node.ID]].Error = fmt.Sprintf("Serial=%d，Primary=%d", serial, primarySerial)
			failures = append(failures, fmt.Sprintf("Secondary %s Serial=%d，Primary=%d", node.Name, serial, primarySerial))
		}
	}
	if len(failures) > 0 {
		return checks, fmt.Errorf("RPZ 集群 SOA 校验失败: %s", strings.Join(failures, "; "))
	}
	for index, node := range nodes {
		for _, rule := range rules {
			if err := verifyRPZRuleAnswer(ctx, node, rule); err != nil {
				checks[index].Status = "sync_exception"
				checks[index].Error = err.Error()
				failures = append(failures, err.Error())
			}
		}
		for _, rule := range removed {
			if err := verifyRPZRuleRemoved(ctx, node, rule); err != nil {
				checks[index].Status = "sync_exception"
				checks[index].Error = err.Error()
				failures = append(failures, err.Error())
			}
		}
	}
	if len(failures) > 0 {
		return checks, fmt.Errorf("RPZ 规则实际解析校验失败: %s", strings.Join(failures, "; "))
	}
	for index := range checks {
		checks[index].Status = "verified"
	}
	return checks, nil
}

func verifyRPZCluster(ctx context.Context, previousSerial int64, rules, removed []RPZRule) ([]RPZNodeCheck, error) {
	var lastErr error
	var lastChecks []RPZNodeCheck
	for attempt := 0; attempt < 20; attempt++ {
		checks, err := verifyRPZClusterOnce(ctx, previousSerial, rules, removed)
		if err == nil {
			return checks, nil
		} else {
			lastErr = err
			lastChecks = checks
		}
		if attempt == 19 {
			break
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return lastChecks, fmt.Errorf("RPZ 集群校验超时: %w", lastErr)
		case <-timer.C:
		}
	}
	return lastChecks, lastErr
}

func runNSUpdate(ctx context.Context, current, previous []RPZRule) error {
	server, port := rpzPrimaryEndpoint()
	if server == "" {
		return fmt.Errorf("RPZ_PRIMARY 未配置，且尚未从已接入的 Primary 节点获得地址")
	}
	keyFile := strings.TrimSpace(os.Getenv("RPZ_KEY_FILE"))
	if keyFile == "" {
		return fmt.Errorf("RPZ_KEY_FILE 未配置")
	}
	if _, err := os.Stat(keyFile); err != nil { // #nosec G703 -- RPZ_KEY_FILE is a protected deployment configuration path validated at startup.
		return fmt.Errorf("RPZ_KEY_FILE 不可读: %w", err)
	}
	currentDomains := map[string]bool{}
	var input strings.Builder
	fmt.Fprintf(&input, "server %s %s\nzone %s\n", server, port, rpzZoneName())
	for _, rule := range current {
		currentDomains[rule.Domain] = true
		for _, trigger := range rpzQNAMETriggers(rule.Domain) {
			name := trigger + "." + rpzZoneName() + "."
			fmt.Fprintf(&input, "update delete %s\n", name)
			if rpzRuleType(rule) == "A" {
				ip := net.ParseIP(strings.TrimSpace(rule.Value))
				if ip == nil || ip.To4() == nil {
					return fmt.Errorf("invalid A record address for %s: %s", rule.Domain, rule.Value)
				}
				fmt.Fprintf(&input, "update add %s 60 A %s\n", name, ip.To4().String())
			} else {
				fmt.Fprintf(&input, "update add %s 60 CNAME rpz-passthru.\n", name)
			}
		}
	}
	for _, rule := range previous {
		if !currentDomains[rule.Domain] {
			for _, trigger := range rpzQNAMETriggers(rule.Domain) {
				fmt.Fprintf(&input, "update delete %s.%s.\n", trigger, rpzZoneName())
			}
		}
	}
	input.WriteString("send\n")
	command := exec.CommandContext(ctx, "nsupdate", "-k", keyFile) // #nosec G702 -- executable is fixed and keyFile is validated deployment configuration.
	command.Stdin = strings.NewReader(input.String())
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nsupdate 失败: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

var runNSUpdateFunc = runNSUpdate

func rpzPublishTimeout() time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RPZ_PUBLISH_TIMEOUT_SECONDS")))
	if err != nil || seconds < 5 || seconds > 300 {
		seconds = 15
	}
	return time.Duration(seconds) * time.Second
}

func rpzPublishRetries() int {
	retries, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RPZ_PUBLISH_RETRIES")))
	if err != nil || retries < 0 || retries > 5 {
		return 2
	}
	return retries
}

func rpzPublishBackoff() time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RPZ_PUBLISH_RETRY_BACKOFF_SECONDS")))
	if err != nil || seconds < 0 || seconds > 30 {
		seconds = 1
	}
	return time.Duration(seconds) * time.Second
}

func runNSUpdateWithRetry(ctx context.Context, current, previous []RPZRule) (int, error) {
	maxAttempts := rpzPublishRetries() + 1
	backoff := rpzPublishBackoff()
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := runNSUpdateFunc(ctx, current, previous); err == nil {
			return attempt, nil
		} else {
			lastErr = err
		}
		if attempt == maxAttempts {
			break
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return attempt, fmt.Errorf("nsupdate 重试中止: %w", ctx.Err())
		case <-timer.C:
		}
	}
	return maxAttempts, lastErr
}

type publishResult struct {
	Status     string
	SyncStatus string
	Message    string
	Validation string
	Attempts   int
	NodeChecks []RPZNodeCheck
}

func performPublish(ctx context.Context, actor, remoteAddr string) (publishResult, error) {
	dnsMu.RLock()
	current := copyRPZRules(state.Rules)
	previous := copyRPZRules(state.Published)
	snapshotRevision := state.RulesRevision
	dnsMu.RUnlock()
	content, err := compileRPZ(current)
	if err != nil {
		return publishResult{}, err
	}
	path, err := writeRPZArtifact(content)
	if err != nil {
		return publishResult{}, fmt.Errorf("RPZ 产物写入失败: %w", err)
	}
	validation := validateRPZ(ctx, path)
	if strings.HasPrefix(validation, "named-checkzone 失败") {
		return publishResult{}, fmt.Errorf("%s", validation)
	}

	mode := rpzConfig("RPZ_PUBLISH_MODE", "artifact")
	currentDomains := make(map[string]struct{}, len(current))
	for _, rule := range current {
		currentDomains[rule.Domain] = struct{}{}
	}
	removed := make([]RPZRule, 0)
	for _, rule := range previous {
		if _, ok := currentDomains[rule.Domain]; !ok {
			removed = append(removed, rule)
		}
	}
	message := fmt.Sprintf("已生成 %s；%s", path, validation)
	status := "compiled"
	attempts := 1
	if mode == "nsupdate" {
		server, port := rpzPrimaryEndpoint()
		if server == "" {
			return publishResult{Status: status}, fmt.Errorf("发布前缺少已接入的 RPZ Primary 地址")
		}
		address := net.JoinHostPort(server, port)
		before, err := probeDNSNode(ctx, address)
		if err != nil {
			return publishResult{Status: status}, fmt.Errorf("发布前 RPZ Primary SOA 探测失败: %w", err)
		}
		previousSerial, err := strconv.ParseInt(before, 10, 64)
		if err != nil {
			return publishResult{Status: status}, fmt.Errorf("发布前 RPZ Primary SOA Serial 无效: %s", before)
		}
		attempts, err = runNSUpdateWithRetry(ctx, current, previous)
		if err != nil {
			return publishResult{Status: "reconcile_required", SyncStatus: "reconcile_required", Attempts: attempts}, fmt.Errorf("nsupdate 结果不确定，需人工核对 Primary/Secondary: %w", err)
		}
		nodeChecks, err := verifyRPZCluster(ctx, previousSerial, current, removed)
		if err != nil {
			return publishResult{Status: "sync_exception", SyncStatus: "sync_exception", NodeChecks: nodeChecks, Attempts: attempts}, err
		}
		resultChecks := nodeChecks
		status = "published"
		message = "已通过 nsupdate 发布到 RPZ Primary"
		return finishPublish(actor, remoteAddr, current, previous, snapshotRevision, validation, mode, status, attempts, message, resultChecks)
	} else if mode != "artifact" {
		return publishResult{}, fmt.Errorf("RPZ_PUBLISH_MODE 只支持 artifact 或 nsupdate")
	}
	return finishPublish(actor, remoteAddr, current, previous, snapshotRevision, validation, mode, status, attempts, message, nil)
}

var performPublishFunc = performPublish

func finishPublish(actor, remoteAddr string, current, previous []RPZRule, snapshotRevision uint64, validation, mode, status string, attempts int, message string, nodeChecks []RPZNodeCheck) (publishResult, error) {

	now := time.Now().UTC().Format(time.RFC3339)
	dnsStateMutationMu.Lock()
	dnsMu.Lock()
	previousRulesState := copyRPZRules(state.Rules)
	previousPublishedState := copyRPZRules(state.Published)
	previousVersionsState := append([]RPZVersion(nil), state.Versions...)
	previousRevision := state.RulesRevision
	for index := range state.Rules {
		if rpzRuleInSnapshot(state.Rules[index], current) {
			state.Rules[index].Status = status
			if state.RulesRevision == snapshotRevision {
				state.Rules[index].UpdatedAt = now
			}
		} else if status == "published" || status == "compiled" {
			state.Rules[index].Status = "draft"
		}
	}
	if status == "published" {
		snapshot := copyRPZRules(current)
		for index := range snapshot {
			snapshot[index].Status = "published"
			snapshot[index].UpdatedAt = now
		}
		state.Published = snapshot
		state.Versions = append([]RPZVersion{{ID: "version-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10), CreatedAt: now, Mode: mode, Rules: snapshot}}, state.Versions...)
		if len(state.Versions) > 20 {
			state.Versions = state.Versions[:20]
		}
	}
	dnsMu.Unlock()
	if err := saveDNSState(); err != nil {
		dnsMu.Lock()
		state.Rules = previousRulesState
		state.Published = previousPublishedState
		state.Versions = previousVersionsState
		state.RulesRevision = previousRevision
		dnsMu.Unlock()
		dnsStateMutationMu.Unlock()
		return publishResult{Status: "reconcile_required", SyncStatus: "reconcile_required", Validation: validation, Attempts: attempts, NodeChecks: nodeChecks}, fmt.Errorf("状态保存失败；外部发布状态需人工核对")
	}
	dnsStateMutationMu.Unlock()
	if err := auditEvent(&http.Request{RemoteAddr: remoteAddr}, actor, "rpz.publish", mode+":"+status); err != nil {
		message += "；审计记录写入失败，需人工核对：" + err.Error()
		return publishResult{Status: "reconcile_required", SyncStatus: "reconcile_required", Message: message, Validation: validation, Attempts: attempts, NodeChecks: nodeChecks}, fmt.Errorf("发布完成但审计记录失败，需人工核对: %w", err)
	}
	rpzRuntimeMu.Lock()
	rpzRuntimeState = rpzRuntime{Mode: mode, LastPublish: now, Message: message, JobStatus: "succeeded"}
	rpzRuntimeMu.Unlock()
	return publishResult{Status: status, SyncStatus: status, Message: message, Validation: validation, Attempts: attempts, NodeChecks: nodeChecks}, nil
}

func runPublishJob(id, actor, remoteAddr string) {
	defer releasePublishJob(id)
	started := time.Now().UTC().Format(time.RFC3339)
	if _, err := updatePublishJob(id, func(job *PublishJob) { job.Status = "running"; job.StartedAt = started }); err != nil {
		rpzRuntimeMu.Lock()
		rpzRuntimeState.JobID = id
		rpzRuntimeState.JobStatus = "reconcile_required"
		rpzRuntimeState.Message = err.Error()
		rpzRuntimeMu.Unlock()
		queueTelegramAlert("publish_state_persist_failed", fmt.Sprintf("🚨 域盾 DNSGuard RPZ 任务状态持久化失败\n任务：%s\n原因：%s", id, err.Error()))
		return
	}
	rpzRuntimeMu.Lock()
	rpzRuntimeState.JobID = id
	rpzRuntimeState.JobStatus = "running"
	rpzRuntimeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), rpzPublishTimeout())
	result, err := performPublishFunc(ctx, actor, remoteAddr)
	cancel()
	finished := time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		jobStatus := "failed"
		if result.Status == "reconcile_required" || result.SyncStatus == "reconcile_required" {
			jobStatus = "reconcile_required"
		}
		if _, persistErr := updatePublishJob(id, func(job *PublishJob) {
			job.Status = jobStatus
			job.SyncStatus = result.SyncStatus
			job.NodeChecks = result.NodeChecks
			job.Error = err.Error()
			job.FinishedAt = finished
			job.Attempts = result.Attempts
		}); persistErr != nil {
			rpzRuntimeMu.Lock()
			rpzRuntimeState.JobID = id
			rpzRuntimeState.JobStatus = "reconcile_required"
			rpzRuntimeState.Message = persistErr.Error()
			rpzRuntimeMu.Unlock()
			queueTelegramAlert("publish_state_persist_failed", fmt.Sprintf("🚨 域盾 DNSGuard RPZ 任务结果无法持久化\n任务：%s\n原因：%s", id, persistErr.Error()))
			return
		}
		rpzRuntimeMu.Lock()
		rpzRuntimeState.JobID = id
		rpzRuntimeState.JobStatus = jobStatus
		rpzRuntimeState.Message = err.Error()
		rpzRuntimeMu.Unlock()
		queueTelegramAlert("publish_failed", fmt.Sprintf("🚨 域盾 DNSGuard RPZ 发布失败\n任务：%s\n原因：%s", id, err.Error()))
		return
	}
	if _, persistErr := updatePublishJob(id, func(job *PublishJob) {
		job.Status = "succeeded"
		job.SyncStatus = result.SyncStatus
		job.NodeChecks = result.NodeChecks
		job.Message = result.Message
		job.Validation = result.Validation
		job.FinishedAt = finished
		job.Attempts = result.Attempts
	}); persistErr != nil {
		rpzRuntimeMu.Lock()
		rpzRuntimeState.JobID = id
		rpzRuntimeState.JobStatus = "reconcile_required"
		rpzRuntimeState.Message = persistErr.Error()
		rpzRuntimeMu.Unlock()
		queueTelegramAlert("publish_state_persist_failed", fmt.Sprintf("🚨 域盾 DNSGuard RPZ 发布完成但任务状态无法持久化\n任务：%s\n原因：%s", id, persistErr.Error()))
		return
	}
	rpzRuntimeMu.Lock()
	rpzRuntimeState.JobID = id
	rpzRuntimeState.JobStatus = "succeeded"
	rpzRuntimeMu.Unlock()
	queueTelegramAlert("rpz_publish_success", fmt.Sprintf("✅ 域盾 DNSGuard RPZ 操作完成\n任务：%s\n结果：%s", id, result.Message))
}

func publishRPZ(w http.ResponseWriter, r *http.Request) {
	publishRPZInternal(w, r, "")
}

func requireBINDReadyForWrite(w http.ResponseWriter) bool {
	// Legacy/dev fixtures do not use the platform-first gate. Preserve their
	// existing behavior; only the explicit first-install mode blocks writes.
	if !platformBootstrapEnabled() || bindReadyStatus() {
		return true
	}
	writeJSON(w, http.StatusPreconditionRequired, map[string]string{
		"error": "BIND 尚未接入；请先在初始化向导中完成 Primary、Secondary、RPZ Zone 和 TSIG 验证，当前只允许保存草稿",
	})
	return false
}

// publishRPZInternal optionally consumes a reservation held by rollbackRPZ.
// The reservation is retained from the rollback state mutation through job
// creation, then atomically handed to runPublishJob.
func publishRPZInternal(w http.ResponseWriter, r *http.Request, reservationID string) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return false
	}
	if !requireBINDReadyForWrite(w) {
		return false
	}
	if job, ok := pendingReconciliationJob(); ok {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":        "存在待人工核对的 RPZ 发布任务，确认 Primary/Secondary 实际状态后再发布",
			"reconcileJob": job.ID,
		})
		return false
	}
	if reservationID != "" && activePublishJob() != reservationID {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "回滚发布预留已失效，请重试"})
		return false
	}
	dnsMu.RLock()
	pending := !rpzRulesEqual(state.Rules, state.Published)
	dnsMu.RUnlock()
	if !pending {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "没有待发布的 RPZ 变更"})
		return false
	}
	now := time.Now().UTC().Format(time.RFC3339)
	job := PublishJob{ID: "publish-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10), Status: "queued", CreatedAt: now}
	reservedID := reservationID
	if reservedID == "" {
		reservedID = job.ID
		if !reservePublishJob(job.ID) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "已有 RPZ 发布任务正在执行", "activeJobId": activePublishJob()})
			return false
		}
	}
	publishJobMu.Lock()
	publishJobs[job.ID] = job
	if len(publishJobs) > 50 {
		for id := range publishJobs {
			if id != job.ID {
				delete(publishJobs, id)
				break
			}
		}
	}
	publishJobMu.Unlock()
	if err := persistPublishJobs(); err != nil {
		releasePublishJob(reservedID)
		_, recoveryErr := updatePublishJob(job.ID, func(job *PublishJob) {
			job.Status = "reconcile_required"
			job.SyncStatus = "reconcile_required"
			job.Error = "任务初始状态持久化失败，未执行 BIND 更新；请人工核对任务文件后恢复"
			job.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		})
		message := "RPZ 发布任务持久化失败，未执行 BIND 更新"
		if recoveryErr != nil {
			message += "；人工核对状态写入也失败: " + recoveryErr.Error()
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": message, "jobId": job.ID})
		return false
	}
	if reservationID != "" && !handoffPublishJob(reservationID, job.ID) {
		releasePublishJob(reservedID)
		_, _ = updatePublishJob(job.ID, func(job *PublishJob) {
			job.Status = "reconcile_required"
			job.SyncStatus = "reconcile_required"
			job.Error = "回滚与发布任务交接失败，禁止执行 BIND 更新"
			job.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		})
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "回滚发布任务交接失败，需人工核对", "jobId": job.ID})
		return false
	}
	rpzRuntimeMu.Lock()
	rpzRuntimeState.JobID = job.ID
	rpzRuntimeState.JobStatus = "queued"
	rpzRuntimeMu.Unlock()
	go runPublishJob(job.ID, authUsername(), requestIP(r))
	writeJSON(w, http.StatusAccepted, job)
	return true
}

func publishJobByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/dns/rpz/jobs/"), "/")
	job, ok := getPublishJob(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func rollbackRPZ(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !requireBINDReadyForWrite(w) {
		return
	}
	if job, ok := pendingReconciliationJob(); ok {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":        "存在待人工核对的 RPZ 发布任务，确认 Primary/Secondary 实际状态后再回滚",
			"reconcileJob": job.ID,
		})
		return
	}
	var request struct {
		VersionID string `json:"versionId"`
	}
	if err := decodeJSON(r, &request); err != nil || strings.TrimSpace(request.VersionID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "versionId required"})
		return
	}
	// Keep the execution slot from the rollback decision through durable state
	// mutation and publish-job creation. A competing publish/rollback therefore
	// cannot enter between the old active check and publishRPZ.
	reservationID := "rollback-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	if !reservePublishJob(reservationID) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "已有 RPZ 发布任务正在执行", "activeJobId": activePublishJob()})
		return
	}
	handedOff := false
	defer func() {
		if !handedOff {
			releasePublishJob(reservationID)
		}
	}()

	now := time.Now().UTC().Format(time.RFC3339)
	dnsStateMutationMu.Lock()
	dnsMu.Lock()
	var target *RPZVersion
	for index := range state.Versions {
		if state.Versions[index].ID == request.VersionID {
			copy := state.Versions[index]
			copy.Rules = copyRPZRules(copy.Rules)
			target = &copy
			break
		}
	}
	if target == nil {
		dnsMu.Unlock()
		dnsStateMutationMu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "version not found"})
		return
	}
	if rpzRulesEqual(target.Rules, state.Published) {
		dnsMu.Unlock()
		dnsStateMutationMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "目标版本已经是当前已发布版本，无需回滚"})
		return
	}
	previousRules := copyRPZRules(state.Rules)
	previousRevision := state.RulesRevision
	state.Rules = copyRPZRules(target.Rules)
	state.RulesRevision++
	for index := range state.Rules {
		state.Rules[index].Status = "draft"
		state.Rules[index].UpdatedAt = now
	}
	dnsMu.Unlock()
	if err := saveDNSState(); err != nil {
		dnsMu.Lock()
		state.Rules = previousRules
		state.RulesRevision = previousRevision
		dnsMu.Unlock()
		dnsStateMutationMu.Unlock()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "回滚状态保存失败"})
		return
	}
	dnsStateMutationMu.Unlock()
	recordCriticalAudit(r, authUsername(), "rpz.rollback", target.ID)
	queueTelegramAlert("rpz_rollback", fmt.Sprintf("↩️ 域盾 DNSGuard RPZ 回滚\n版本：%s\n规则数：%d", target.ID, len(target.Rules)))
	if publishRPZInternal(w, r, reservationID) {
		handedOff = true
	}
}
