package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	ID         string `json:"id"`
	Status     string `json:"status"`
	Message    string `json:"message,omitempty"`
	Validation string `json:"validation,omitempty"`
	Error      string `json:"error,omitempty"`
	CreatedAt  string `json:"createdAt"`
	StartedAt  string `json:"startedAt,omitempty"`
	FinishedAt string `json:"finishedAt,omitempty"`
}

var rpzRuntimeMu sync.RWMutex
var rpzRuntimeState = rpzRuntime{Mode: "artifact", Message: "尚未发布", JobStatus: "idle"}
var publishJobMu sync.RWMutex
var publishJobs = map[string]PublishJob{}

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

func updatePublishJob(id string, update func(*PublishJob)) PublishJob {
	publishJobMu.Lock()
	job := publishJobs[id]
	update(&job)
	publishJobs[id] = job
	publishJobMu.Unlock()
	return job
}

func getPublishJob(id string) (PublishJob, bool) {
	publishJobMu.RLock()
	job, ok := publishJobs[id]
	publishJobMu.RUnlock()
	return job, ok
}

func rpzZoneName() string {
	return rpzConfig("RPZ_ZONE", "rpz.local")
}

func rpzQNAMETriggers(domain string) []string {
	return []string{domain, "*." + domain}
}

func compileRPZ(rules []RPZRule) (string, error) {
	serial := time.Now().UTC().Unix()
	zone := rpzZoneName()
	var builder strings.Builder
	fmt.Fprintf(&builder, "$TTL 60\n$ORIGIN %s.\n@ SOA localhost. hostmaster.localhost. (%d 1h 15m 30d 60)\n  NS localhost.\n\n", zone, serial)
	for _, rule := range rules {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.Domain), "."))
		if !domainPattern.MatchString(domain) {
			return "", fmt.Errorf("invalid RPZ domain: %s", rule.Domain)
		}
		for _, trigger := range rpzQNAMETriggers(domain) {
			fmt.Fprintf(&builder, "%s.%s. 60 CNAME rpz-passthru. ; %s\n", trigger, zone, strings.ReplaceAll(rule.Reason, "\n", " "))
		}
	}
	return builder.String(), nil
}

func activeRPZRules() []RPZRule {
	dnsMu.RLock()
	defer dnsMu.RUnlock()
	return append([]RPZRule{}, state.Rules...)
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

func runNSUpdate(ctx context.Context, current, previous []RPZRule) error {
	server := rpzConfig("RPZ_PRIMARY", "RPZ_PRIMARY")
	port := rpzConfig("RPZ_PRIMARY_PORT", "53")
	keyFile := strings.TrimSpace(os.Getenv("RPZ_KEY_FILE"))
	if keyFile == "" {
		return fmt.Errorf("RPZ_KEY_FILE 未配置")
	}
	if _, err := os.Stat(keyFile); err != nil {
		return fmt.Errorf("RPZ_KEY_FILE 不可读: %w", err)
	}
	currentDomains := map[string]bool{}
	var input strings.Builder
	fmt.Fprintf(&input, "server %s %s\nzone %s\n", server, port, rpzZoneName())
	for _, rule := range current {
		currentDomains[rule.Domain] = true
		for _, trigger := range rpzQNAMETriggers(rule.Domain) {
			fmt.Fprintf(&input, "update delete %s.%s. CNAME\n", trigger, rpzZoneName())
			fmt.Fprintf(&input, "update add %s.%s. 60 CNAME rpz-passthru.\n", trigger, rpzZoneName())
		}
	}
	for _, rule := range previous {
		if !currentDomains[rule.Domain] {
			for _, trigger := range rpzQNAMETriggers(rule.Domain) {
				fmt.Fprintf(&input, "update delete %s.%s. CNAME\n", trigger, rpzZoneName())
			}
		}
	}
	input.WriteString("send\n")
	command := exec.CommandContext(ctx, "nsupdate", "-k", keyFile)
	command.Stdin = strings.NewReader(input.String())
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nsupdate 失败: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

type publishResult struct {
	Status     string
	Message    string
	Validation string
}

func performPublish(ctx context.Context, actor, remoteAddr string) (publishResult, error) {
	current := activeRPZRules()
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
	dnsMu.RLock()
	previous := append([]RPZRule(nil), state.Published...)
	dnsMu.RUnlock()
	message := fmt.Sprintf("已生成 %s；%s", path, validation)
	status := "compiled"
	if mode == "nsupdate" {
		if err := runNSUpdate(ctx, current, previous); err != nil {
			return publishResult{}, err
		}
		status = "published"
		message = "已通过 nsupdate 发布到 RPZ Primary"
	} else if mode != "artifact" {
		return publishResult{}, fmt.Errorf("RPZ_PUBLISH_MODE 只支持 artifact 或 nsupdate")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	dnsMu.Lock()
	for index := range state.Rules {
		state.Rules[index].Status = status
		state.Rules[index].UpdatedAt = now
	}
	if status == "published" {
		snapshot := copyRPZRules(current)
		state.Published = snapshot
		state.Versions = append([]RPZVersion{{ID: "version-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10), CreatedAt: now, Mode: mode, Rules: snapshot}}, state.Versions...)
		if len(state.Versions) > 20 {
			state.Versions = state.Versions[:20]
		}
	}
	dnsMu.Unlock()
	if err := saveDNSState(); err != nil {
		return publishResult{}, fmt.Errorf("状态保存失败")
	}
	rpzRuntimeMu.Lock()
	rpzRuntimeState = rpzRuntime{Mode: mode, LastPublish: now, Message: message, JobStatus: "succeeded"}
	rpzRuntimeMu.Unlock()
	auditEvent(&http.Request{RemoteAddr: remoteAddr}, actor, "rpz.publish", mode+":"+status)
	return publishResult{Status: status, Message: message, Validation: validation}, nil
}

func runPublishJob(id, actor, remoteAddr string) {
	started := time.Now().UTC().Format(time.RFC3339)
	updatePublishJob(id, func(job *PublishJob) { job.Status = "running"; job.StartedAt = started })
	rpzRuntimeMu.Lock()
	rpzRuntimeState.JobID = id
	rpzRuntimeState.JobStatus = "running"
	rpzRuntimeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	result, err := performPublish(ctx, actor, remoteAddr)
	cancel()
	finished := time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		updatePublishJob(id, func(job *PublishJob) { job.Status = "failed"; job.Error = err.Error(); job.FinishedAt = finished })
		rpzRuntimeMu.Lock()
		rpzRuntimeState.JobID = id
		rpzRuntimeState.JobStatus = "failed"
		rpzRuntimeState.Message = err.Error()
		rpzRuntimeMu.Unlock()
		return
	}
	updatePublishJob(id, func(job *PublishJob) {
		job.Status = "succeeded"
		job.Message = result.Message
		job.Validation = result.Validation
		job.FinishedAt = finished
	})
	rpzRuntimeMu.Lock()
	rpzRuntimeState.JobID = id
	rpzRuntimeState.JobStatus = "succeeded"
	rpzRuntimeMu.Unlock()
}

func publishRPZ(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	job := PublishJob{ID: "publish-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10), Status: "queued", CreatedAt: now}
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
	rpzRuntimeMu.Lock()
	rpzRuntimeState.JobID = job.ID
	rpzRuntimeState.JobStatus = "queued"
	rpzRuntimeMu.Unlock()
	go runPublishJob(job.ID, authUsername(), requestIP(r))
	writeJSON(w, http.StatusAccepted, job)
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
	var request struct {
		VersionID string `json:"versionId"`
	}
	if err := decodeJSON(r, &request); err != nil || strings.TrimSpace(request.VersionID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "versionId required"})
		return
	}
	dnsMu.RLock()
	var target *RPZVersion
	for index := range state.Versions {
		if state.Versions[index].ID == request.VersionID {
			copy := state.Versions[index]
			copy.Rules = copyRPZRules(copy.Rules)
			target = &copy
			break
		}
	}
	dnsMu.RUnlock()
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "version not found"})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	dnsMu.Lock()
	state.Rules = copyRPZRules(target.Rules)
	for index := range state.Rules {
		state.Rules[index].Status = "draft"
		state.Rules[index].UpdatedAt = now
	}
	dnsMu.Unlock()
	if err := saveDNSState(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "回滚状态保存失败"})
		return
	}
	auditEvent(r, authUsername(), "rpz.rollback", target.ID)
	publishRPZ(w, r)
}
