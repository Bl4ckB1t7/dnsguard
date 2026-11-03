package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type rpzRuntime struct {
	Mode        string
	LastPublish string
	Message     string
}

var rpzRuntimeMu sync.RWMutex
var rpzRuntimeState = rpzRuntime{Mode: "artifact", Message: "尚未发布"}

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

func publishRPZ(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	current := activeRPZRules()
	content, err := compileRPZ(current)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	path, err := writeRPZArtifact(content)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "RPZ 产物写入失败: " + err.Error()})
		return
	}
	validation := validateRPZ(ctx, path)
	if strings.HasPrefix(validation, "named-checkzone 失败") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": validation})
		return
	}

	mode := rpzConfig("RPZ_PUBLISH_MODE", "artifact")
	dnsMu.RLock()
	previous := append([]RPZRule(nil), state.Published...)
	dnsMu.RUnlock()
	message := fmt.Sprintf("已生成 %s；%s", path, validation)
	status := "compiled"
	if mode == "nsupdate" {
		if err := runNSUpdate(ctx, current, previous); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		status = "published"
		message = "已通过 nsupdate 发布到 RPZ Primary"
	} else if mode != "artifact" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "RPZ_PUBLISH_MODE 只支持 artifact 或 nsupdate"})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	dnsMu.Lock()
	for index := range state.Rules {
		state.Rules[index].Status = status
		state.Rules[index].UpdatedAt = now
	}
	if status == "published" {
		state.Published = append([]RPZRule{}, current...)
	}
	dnsMu.Unlock()
	if err := saveDNSState(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "状态保存失败"})
		return
	}
	rpzRuntimeMu.Lock()
	rpzRuntimeState = rpzRuntime{Mode: mode, LastPublish: now, Message: message}
	rpzRuntimeMu.Unlock()
	auditEvent(r, authUsername(), "rpz.publish", mode+":"+status)
	writeJSON(w, http.StatusOK, map[string]string{"status": status, "message": message, "validation": validation})
}
