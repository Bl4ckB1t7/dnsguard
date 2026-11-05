//lint:file-ignore ST1005 Setup validation errors are user-facing localized messages.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	"golang.org/x/crypto/bcrypt"
)

const (
	initializationPending   = "pending"
	initializationCompleted = "completed"
	initializationFailed    = "failed"
)

type initializationState struct {
	Status       string `json:"status"`
	Version      int    `json:"version"`
	StartedAt    string `json:"startedAt,omitempty"`
	CompletedAt  string `json:"completedAt,omitempty"`
	Username     string `json:"username,omitempty"`
	Zone         string `json:"zone,omitempty"`
	Primary      string `json:"primary,omitempty"`
	SecondaryCnt int    `json:"secondaryCount,omitempty"`
	Error        string `json:"error,omitempty"`
	PolicyMode   string `json:"policyMode,omitempty"`

	// These fields make an interrupted setup recoverable. They never contain
	// passwords, tokens, or TSIG material.
	BackupDir       string `json:"backupDir,omitempty"`
	AuthExisted     bool   `json:"authExisted,omitempty"`
	NodesExisted    bool   `json:"nodesExisted,omitempty"`
	DNSStateExisted bool   `json:"dnsStateExisted,omitempty"`
}

type setupNode struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Address string `json:"address"`
}

type setupRequest struct {
	Username    string      `json:"username"`
	Password    string      `json:"password"`
	Zone        string      `json:"zone"`
	Primary     setupNode   `json:"primary"`
	Secondaries []setupNode `json:"secondaries"`
	TSIGKeyPath string      `json:"tsigKeyPath"`
	WriteTest   bool        `json:"writeTest"`
}

type setupCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // pass, fail, not_run
	Detail  string `json:"detail"`
	Impact  string `json:"impact,omitempty"`
	Cleanup string `json:"cleanup,omitempty"`
}

type setupCheckResult struct {
	Ready  bool         `json:"ready"`
	Checks []setupCheck `json:"checks"`
	Error  string       `json:"error,omitempty"`
}

var initializationMu sync.Mutex
var initializationFileMu sync.Mutex
var setupTransactionMu sync.Mutex
var initialization = initializationState{}

// setupChecksFunc is injectable so unit tests can exercise the transaction
// and concurrency rules without making an external DNS write.
var setupChecksFunc = runSetupChecks

func initializationFilePath() string {
	if path := strings.TrimSpace(os.Getenv("INITIALIZATION_FILE")); path != "" {
		return path
	}
	return filepath.Join(filepath.Dir(dnsStatePath()), "initialization.json")
}

func bootstrapTokenFilePath() string {
	if path := strings.TrimSpace(os.Getenv("BOOTSTRAP_TOKEN_FILE")); path != "" {
		return path
	}
	return filepath.Join(filepath.Dir(strings.TrimSpace(os.Getenv("RPZ_KEY_FILE"))), "bootstrap.token")
}

func bootstrapKeyDir() string {
	if path := strings.TrimSpace(os.Getenv("BOOTSTRAP_KEY_DIR")); path != "" {
		return filepath.Clean(path)
	}
	if path := strings.TrimSpace(os.Getenv("RPZ_KEY_FILE")); path != "" {
		return filepath.Dir(path)
	}
	return "."
}

func writeAtomicSetupFile(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".dnsguard-setup-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
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
}

func saveInitializationState() error {
	initializationFileMu.Lock()
	defer initializationFileMu.Unlock()
	initializationMu.Lock()
	copyState := initialization
	initializationMu.Unlock()
	content, err := json.MarshalIndent(copyState, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicSetupFile(initializationFilePath(), append(content, '\n'), 0o600)
}

func loadInitializationState() error {
	content, err := os.ReadFile(initializationFilePath())
	if os.IsNotExist(err) {
		initializationMu.Lock()
		initialization = initializationState{}
		initializationMu.Unlock()
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取初始化状态失败: %w", err)
	}
	var loaded initializationState
	if err := json.Unmarshal(content, &loaded); err != nil {
		return fmt.Errorf("初始化状态文件损坏: %w", err)
	}
	initializationMu.Lock()
	initialization = loaded
	initializationMu.Unlock()
	if loaded.Status == initializationPending {
		if err := recoverInterruptedSetup(loaded); err != nil {
			return fmt.Errorf("恢复中断的初始化失败: %w", err)
		}
		initializationMu.Lock()
		initialization.Status = initializationFailed
		initialization.Error = "上一次初始化中断，已回滚临时文件；请重新验证配置"
		initialization.BackupDir = ""
		initializationMu.Unlock()
		return saveInitializationState()
	}
	return nil
}

func isInitialized() bool {
	// Development fixtures intentionally disable authentication and provide
	// their own node/state files. Keep that legacy local mode usable; the
	// production preflight always requires AUTH_ENABLED=true and therefore
	// cannot bypass the first-run gate this way.
	if !authEnabled() && !strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production") {
		return true
	}
	initializationMu.Lock()
	status := initialization.Status
	initializationMu.Unlock()
	if status == initializationPending {
		return false
	}
	if status == initializationCompleted {
		return authFileHasPasswordHash() && regularFileExists(dnsNodeConfigPath())
	}
	if status == initializationFailed {
		return false
	}
	// Existing installations that predate the marker have valid auth and node
	// files; treat them as initialized and never overwrite them.
	return authFileHasPasswordHash() && regularFileExists(dnsNodeConfigPath())
}

func initializationInProgress() bool {
	initializationMu.Lock()
	defer initializationMu.Unlock()
	return initialization.Status == initializationPending
}

func regularFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func setupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	initializationMu.Lock()
	current := initialization
	initializationMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"initialized":       isInitialized(),
		"inProgress":        current.Status == initializationPending,
		"status":            current.Status,
		"error":             current.Error,
		"tsigKeyPath":       strings.TrimSpace(os.Getenv("RPZ_KEY_FILE")),
		"keyCandidates":     protectedKeyCandidates(),
		"writeTestRequired": true,
		"policyMode":        configuredPolicyMode(),
		"whitelistSeed":     inspectWhitelistSeed(),
	})
}

func protectedKeyCandidates() []string {
	root := bootstrapKeyDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		return []string{}
	}
	result := make([]string, 0)
	for _, entry := range entries {
		if entry.Name() == filepath.Base(bootstrapTokenFilePath()) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 {
			continue
		}
		result = append(result, path)
	}
	return result
}

func setupToken(r *http.Request) (string, error) {
	content, err := os.ReadFile(bootstrapTokenFilePath())
	if err != nil {
		return "", fmt.Errorf("Bootstrap Token 不可用")
	}
	info, err := os.Stat(bootstrapTokenFilePath())
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 {
		return "", fmt.Errorf("Bootstrap Token 文件权限不安全")
	}
	expected := strings.TrimSpace(string(content))
	provided := strings.TrimSpace(r.Header.Get("X-DNSGuard-Bootstrap"))
	if len(expected) < 32 || subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) != 1 {
		return "", fmt.Errorf("Bootstrap Token 无效")
	}
	return expected, nil
}

func validateBootstrapTokenFile() error {
	path := bootstrapTokenFilePath()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("Bootstrap Token 文件必须存在且为普通文件")
	}
	if info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("Bootstrap Token 文件不得对其他用户开放")
	}
	content, err := os.ReadFile(path)
	if err != nil || len(strings.TrimSpace(string(content))) < 32 {
		return fmt.Errorf("Bootstrap Token 长度不足")
	}
	return nil
}

func normalizeSetupZone(zone string) (string, error) {
	zone = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(zone)), ".")
	if !domainPattern.MatchString(zone) {
		return "", fmt.Errorf("RPZ Zone 格式无效")
	}
	return zone + ".", nil
}

func validateSetupKey(path string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !pathWithin(bootstrapKeyDir(), path) {
		return fmt.Errorf("TSIG Key 只能从受保护部署目录选择")
	}
	info, err := os.Lstat(path) // #nosec G703 -- path is constrained to the protected bootstrap key directory.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("TSIG Key 必须是受保护的普通文件")
	}
	if info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("TSIG Key 不得对其他用户开放")
	}
	if info.Size() == 0 {
		return fmt.Errorf("TSIG Key 不能为空")
	}
	return nil
}

func pathWithin(root, path string) bool {
	root, _ = filepath.Abs(filepath.Clean(root))
	path, _ = filepath.Abs(filepath.Clean(path))
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "."
}

var setupUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

func validateSetupRequest(request setupRequest) (setupRequest, []DNSNode, error) {
	request.Username = strings.TrimSpace(request.Username)
	request.Zone = strings.TrimSpace(request.Zone)
	if !setupUsernamePattern.MatchString(request.Username) {
		return request, nil, fmt.Errorf("管理员用户名格式无效")
	}
	if len(request.Password) < 12 {
		return request, nil, fmt.Errorf("管理员密码至少需要 12 位")
	}
	zone, err := normalizeSetupZone(request.Zone)
	if err != nil {
		return request, nil, err
	}
	request.Zone = zone
	if configuredZone := strings.TrimSpace(os.Getenv("RPZ_ZONE")); configuredZone != "" {
		configuredZone, zoneErr := normalizeSetupZone(configuredZone)
		if zoneErr != nil || !strings.EqualFold(configuredZone, request.Zone) {
			return request, nil, fmt.Errorf("向导 Zone 必须与部署配置 RPZ_ZONE 一致")
		}
	}
	if request.TSIGKeyPath == "" {
		request.TSIGKeyPath = strings.TrimSpace(os.Getenv("RPZ_KEY_FILE"))
	}
	if configuredKey := strings.TrimSpace(os.Getenv("RPZ_KEY_FILE")); configuredKey != "" && filepath.Clean(request.TSIGKeyPath) != filepath.Clean(configuredKey) {
		return request, nil, fmt.Errorf("TSIG Key 必须使用部署配置 RPZ_KEY_FILE 指向的受保护文件")
	}
	if err := validateSetupKey(request.TSIGKeyPath); err != nil {
		return request, nil, err
	}
	if request.Primary.Role != "" && strings.ToLower(strings.TrimSpace(request.Primary.Role)) != "primary" {
		return request, nil, fmt.Errorf("Primary 角色必须为 primary")
	}
	if !dnsNodeAddressAllowed(request.Primary.Address) {
		return request, nil, fmt.Errorf("Primary 地址无效或不在允许范围内")
	}
	if configuredPrimary := strings.TrimSpace(os.Getenv("RPZ_PRIMARY")); configuredPrimary != "" && !strings.Contains(configuredPrimary, "DNS_PRIMARY") {
		configuredPort := strings.TrimSpace(os.Getenv("RPZ_PRIMARY_PORT"))
		if configuredPort == "" {
			configuredPort = "53"
		}
		if _, _, splitErr := net.SplitHostPort(configuredPrimary); splitErr != nil {
			configuredPrimary = net.JoinHostPort(strings.Trim(configuredPrimary, "[]"), configuredPort)
		}
		configuredHost, configuredPortValue := splitDNSAddress(configuredPrimary)
		requestHost, requestPort := splitDNSAddress(request.Primary.Address)
		if !strings.EqualFold(configuredHost, requestHost) || configuredPortValue != requestPort {
			return request, nil, fmt.Errorf("Primary 地址必须与部署配置 RPZ_PRIMARY/RPZ_PRIMARY_PORT 一致")
		}
	}
	if len(request.Secondaries) < 1 {
		return request, nil, fmt.Errorf("至少需要一个 Secondary")
	}
	nodes := []DNSNode{{ID: "primary-1", Name: setupNodeName(request.Primary.Name, "BIND-PRIMARY"), Role: "primary", Address: strings.TrimSpace(request.Primary.Address)}}
	seen := map[string]bool{strings.ToLower(nodes[0].Address): true}
	for index, secondary := range request.Secondaries {
		if !dnsNodeAddressAllowed(secondary.Address) {
			return request, nil, fmt.Errorf("Secondary %d 地址无效或不在允许范围内", index+1)
		}
		address := strings.ToLower(strings.TrimSpace(secondary.Address))
		if seen[address] {
			return request, nil, fmt.Errorf("DNS 节点地址重复")
		}
		seen[address] = true
		nodes = append(nodes, DNSNode{ID: fmt.Sprintf("secondary-%d", index+1), Name: setupNodeName(secondary.Name, fmt.Sprintf("BIND-SECONDARY-%d", index+1)), Role: "secondary", Address: strings.TrimSpace(secondary.Address)})
	}
	if err := validateDNSNodeSet(nodes); err != nil {
		return request, nil, err
	}
	return request, nodes, nil
}

func setupNodeName(name, fallback string) string {
	if name = strings.TrimSpace(name); name != "" {
		return name
	}
	return fallback
}

func setupValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if isInitialized() || initializationInProgress() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "系统已经初始化或正在初始化"})
		return
	}
	if _, err := setupToken(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	var request setupRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}
	request, _, err := validateSetupRequest(request)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if _, err := loadWhitelistSeedForZone(request.Zone); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "白名单初始 JSON 校验失败：" + err.Error()})
		return
	}
	result := setupChecksFunc(r.Context(), request)
	status := http.StatusOK
	if !result.Ready {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, result)
}

func setupComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if initializationInProgress() || isInitialized() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "系统已经初始化或正在初始化"})
		return
	}
	setupTransactionMu.Lock()
	defer setupTransactionMu.Unlock()
	if initializationInProgress() || isInitialized() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "系统已经初始化或正在初始化"})
		return
	}
	if _, err := setupToken(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	var request setupRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}
	request, nodes, err := validateSetupRequest(request)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	seedRules, err := loadWhitelistSeedForZone(request.Zone)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "白名单初始 JSON 校验失败：" + err.Error()})
		return
	}
	result := setupChecksFunc(r.Context(), request)
	if !result.Ready {
		writeJSON(w, http.StatusUnprocessableEntity, result)
		return
	}
	if err := commitSetup(request, nodes, seedRules, r); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "初始化未完成：" + err.Error()})
		return
	}
	issueSetupSession(w, r, request.Username)
	writeJSON(w, http.StatusOK, map[string]any{"initialized": true, "authenticated": true, "username": request.Username})
}

func issueSetupSession(w http.ResponseWriter, r *http.Request, username string) {
	expiry := time.Now().Add(8 * time.Hour).Unix()
	sessionID, err := newSessionID()
	if err != nil {
		return
	}
	csrfToken, err := newCSRFToken()
	if err != nil {
		return
	}
	authMu.Lock()
	activeSessions[username] = sessionID
	authMu.Unlock()
	secure := r.TLS != nil || (trustedProxy(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure -- secure is derived from TLS or an explicitly trusted proxy.
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: signSession(username, expiry, sessionID), Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 8 * 60 * 60})
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure,go.lang.security.audit.net.cookie-missing-httponly.cookie-missing-httponly -- CSRF is intentionally readable by the browser and secure follows TLS/proxy state.
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrfToken, Path: "/", Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 8 * 60 * 60})
}

func commitSetup(request setupRequest, nodes []DNSNode, seedRules []RPZRule, r *http.Request) error {
	backupDir, err := os.MkdirTemp(filepath.Dir(dnsStatePath()), ".dnsguard-setup-backup-")
	if err != nil {
		return err
	}
	paths := []string{authFilePath(), dnsNodeConfigPath(), dnsStatePath()}
	existed := []bool{regularFileExists(paths[0]), regularFileExists(paths[1]), regularFileExists(paths[2])}
	for index, path := range paths {
		if existed[index] {
			content, readErr := os.ReadFile(path)
			if readErr != nil || os.WriteFile(filepath.Join(backupDir, strconv.Itoa(index)), content, 0o600) != nil { // #nosec G703 -- backupDir is freshly created and the filename is a local numeric index.
				_ = os.RemoveAll(backupDir)
				return fmt.Errorf("备份现有配置失败")
			}
		}
	}
	initializationMu.Lock()
	initialization = initializationState{Status: initializationPending, Version: 1, StartedAt: time.Now().UTC().Format(time.RFC3339), Username: request.Username, Zone: request.Zone, Primary: nodes[0].Address, SecondaryCnt: len(nodes) - 1, PolicyMode: configuredPolicyMode(), BackupDir: backupDir, AuthExisted: existed[0], NodesExisted: existed[1], DNSStateExisted: existed[2]}
	initializationMu.Unlock()
	if err := saveInitializationState(); err != nil {
		_ = os.RemoveAll(backupDir)
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return recoverSetupAndFail(fmt.Errorf("管理员密码哈希失败: %w", err))
	}
	authContent, _ := json.MarshalIndent(authStore{Username: request.Username, PasswordHash: string(hash), MustChangePassword: false}, "", "  ")
	nodeContent, _ := json.MarshalIndent(nodeConfigsFromNodes(nodes), "", "  ")
	dnsMu.RLock()
	newState := state
	newState.Nodes = nodes
	newState.Rules = append([]RPZRule(nil), seedRules...)
	newState.Published = []RPZRule{}
	newState.Versions = []RPZVersion{}
	newState.RulesRevision = uint64(len(seedRules))
	newState.PolicyMode = configuredPolicyMode()
	dnsMu.RUnlock()
	stateContent, _ := json.MarshalIndent(newState, "", "  ")
	stages := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{authFilePath(), append(authContent, '\n'), 0o600},
		{dnsNodeConfigPath(), append(nodeContent, '\n'), 0o640},
		{dnsStatePath(), append(stateContent, '\n'), 0o640},
	}
	for index, stage := range stages {
		if err := writeAtomicSetupFile(stage.path, stage.data, stage.mode); err != nil {
			return recoverSetupAndFail(fmt.Errorf("写入初始化配置失败: %w", err))
		}
		if failAfter := strings.TrimSpace(os.Getenv("DNSGUARD_SETUP_FAIL_AFTER")); failAfter != "" && failAfter == []string{"auth", "nodes", "state"}[index] {
			return recoverSetupAndFail(fmt.Errorf("初始化在测试注入点中断"))
		}
	}
	loadAuth()
	dnsMu.Lock()
	state = newState
	dnsMu.Unlock()
	if len(seedRules) > 0 {
		if err := recordCriticalAudit(r, request.Username, "setup.whitelist.import", fmt.Sprintf("count=%d source=rpz-connect mode=global status=draft", len(seedRules))); err != nil {
			return recoverSetupAndFail(fmt.Errorf("白名单导入审计记录失败: %w", err))
		}
	}
	if err := recordCriticalAudit(r, request.Username, "setup.complete", "success"); err != nil {
		return recoverSetupAndFail(fmt.Errorf("审计记录失败: %w", err))
	}
	initializationMu.Lock()
	initialization.Status = initializationCompleted
	initialization.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	initialization.Error = ""
	initialization.BackupDir = ""
	initializationMu.Unlock()
	if err := saveInitializationState(); err != nil {
		return recoverSetupAndFail(fmt.Errorf("初始化状态持久化失败: %w", err))
	}
	_ = os.RemoveAll(backupDir)
	return nil
}

func nodeConfigsFromNodes(nodes []DNSNode) []DNSNodeConfig {
	configs := make([]DNSNodeConfig, 0, len(nodes))
	for _, node := range nodes {
		configs = append(configs, DNSNodeConfig{ID: node.ID, Name: node.Name, Role: node.Role, Address: node.Address})
	}
	return configs
}

func recoverSetupAndFail(cause error) error {
	initializationMu.Lock()
	current := initialization
	initializationMu.Unlock()
	if recoveryErr := recoverInterruptedSetup(current); recoveryErr != nil {
		initializationMu.Lock()
		initialization.Error = "初始化失败且恢复未完成，必须人工核对配置文件"
		initialization.Status = initializationFailed
		initialization.BackupDir = current.BackupDir
		initializationMu.Unlock()
		if saveErr := saveInitializationState(); saveErr != nil {
			return fmt.Errorf("%v；恢复失败: %v；状态写入失败: %w", cause, recoveryErr, saveErr)
		}
		return fmt.Errorf("%v；恢复失败: %v", cause, recoveryErr)
	}
	initializationMu.Lock()
	initialization.Status = initializationFailed
	initialization.Error = "初始化失败，配置已恢复；请检查错误后重试"
	initialization.BackupDir = ""
	initializationMu.Unlock()
	if err := saveInitializationState(); err != nil {
		return fmt.Errorf("%v；恢复状态写入失败: %w", cause, err)
	}
	return cause
}

func recoverInterruptedSetup(current initializationState) error {
	paths := []string{authFilePath(), dnsNodeConfigPath(), dnsStatePath()}
	existed := []bool{current.AuthExisted, current.NodesExisted, current.DNSStateExisted}
	if current.BackupDir != "" {
		for index, path := range paths {
			backup := filepath.Join(current.BackupDir, strconv.Itoa(index))
			if existed[index] {
				if content, err := os.ReadFile(backup); err == nil {
					if err := writeAtomicSetupFile(path, content, map[int]os.FileMode{0: 0o600, 1: 0o640, 2: 0o640}[index]); err != nil {
						return err
					}
				}
			} else {
				_ = os.Remove(path)
			}
		}
		_ = os.RemoveAll(current.BackupDir)
	}
	return nil
}

func runSetupChecks(ctx context.Context, request setupRequest) setupCheckResult {
	checks := make([]setupCheck, 0, 10)
	primarySerial, primaryCheck := querySetupSOA(ctx, "Primary SOA / Zone", request.Primary.Address, request.Zone)
	checks = append(checks, primaryCheck)
	for index, secondary := range request.Secondaries {
		serial, check := querySetupSOA(ctx, fmt.Sprintf("Secondary %d SOA / Zone", index+1), secondary.Address, request.Zone)
		if primarySerial != "" && serial != "" && primarySerial != serial {
			check.Status = "fail"
			check.Detail = fmt.Sprintf("SOA Serial=%s，与 Primary Serial=%s 不一致", serial, primarySerial)
		}
		checks = append(checks, check)
	}
	if configuredPolicyMode() == "global" {
		checks = append(checks, runGlobalDenyChecks(ctx, request)...)
	}
	if !request.WriteTest {
		checks = append(checks, setupCheck{Name: "TSIG 动态更新权限", Status: "not_run", Detail: "未执行写权限验证；只读 SOA 检查不能证明 nsupdate 权限", Impact: "完整验证会在 Primary Zone 临时写入一条 TXT 记录", Cleanup: "不执行写测试，因此没有临时记录"})
	} else {
		checks = append(checks, setupTSIGProbe(ctx, request))
	}
	ready := true
	for _, check := range checks {
		if check.Status != "pass" {
			ready = false
		}
	}
	return setupCheckResult{Ready: ready, Checks: checks}
}

func runGlobalDenyChecks(ctx context.Context, request setupRequest) []setupCheck {
	zone := configuredGlobalDenyZone()
	if zone == "" || !domainPattern.MatchString(zone) {
		return []setupCheck{{Name: "全局默认拒绝 Zone", Status: "fail", Detail: "RPZ_GLOBAL_DENY_ZONE 未配置或格式无效"}}
	}
	checks := make([]setupCheck, 0, len(request.Secondaries)+2)
	primarySerial, check := querySetupSOA(ctx, "全局拒绝 Primary Zone", request.Primary.Address, zone)
	checks = append(checks, check)
	for index, secondary := range request.Secondaries {
		serial, secondaryCheck := querySetupSOA(ctx, fmt.Sprintf("全局拒绝 Secondary %d Zone", index+1), secondary.Address, zone)
		if primarySerial != "" && serial != "" && primarySerial != serial {
			secondaryCheck.Status = "fail"
			secondaryCheck.Detail = fmt.Sprintf("SOA Serial=%s，与全局拒绝 Primary Serial=%s 不一致", serial, primarySerial)
		}
		checks = append(checks, secondaryCheck)
	}
	recursor := strings.TrimSpace(os.Getenv("RPZ_GLOBAL_DENY_RECURSOR"))
	checkName := strings.TrimSpace(os.Getenv("RPZ_GLOBAL_DENY_CHECK_NAME"))
	if recursor == "" || checkName == "" {
		checks = append(checks, setupCheck{Name: "全局拒绝递归效果", Status: "not_run", Detail: "未配置 RPZ_GLOBAL_DENY_RECURSOR 和 RPZ_GLOBAL_DENY_CHECK_NAME", Impact: "仅 SOA 一致不能证明递归策略已生效"})
		return checks
	}
	rcode, rcodeCheck := querySetupRcode(ctx, recursor, checkName)
	if rcodeCheck.Status == "pass" && rcode != "NXDOMAIN" {
		rcodeCheck.Status = "fail"
		rcodeCheck.Detail = "递归策略返回 " + rcode + "，预期 NXDOMAIN"
	}
	checks = append(checks, rcodeCheck)
	return checks
}

func querySetupSOA(ctx context.Context, name, address, zone string) (string, setupCheck) {
	host, port := splitDNSAddress(address)
	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(commandCtx, "dig", "@"+host, "-p", port, zone, "SOA", "+short", "+time=2", "+tries=1").Output()
	if err != nil {
		return "", setupCheck{Name: name, Status: "fail", Detail: "无法读取 SOA：网络不可达或 Zone 不存在"}
	}
	fields := strings.Fields(string(output))
	if len(fields) < 3 {
		return "", setupCheck{Name: name, Status: "fail", Detail: "SOA 响应格式无效"}
	}
	serial := fields[2]
	if _, err := strconv.ParseUint(serial, 10, 32); err != nil {
		return "", setupCheck{Name: name, Status: "fail", Detail: "SOA Serial 无效"}
	}
	return serial, setupCheck{Name: name, Status: "pass", Detail: "可读取 Zone SOA，Serial=" + serial}
}

func querySetupRcode(ctx context.Context, address, name string) (string, setupCheck) {
	host, port := splitDNSAddress(address)
	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(commandCtx, "dig", "@"+host, "-p", port, name, "A", "+comments", "+time=2", "+tries=1").CombinedOutput()
	if err != nil {
		return "", setupCheck{Name: "全局拒绝递归效果", Status: "fail", Detail: "无法读取递归策略 RCODE"}
	}
	for _, line := range strings.Split(string(output), "\n") {
		if marker := strings.Index(line, "status: "); marker >= 0 {
			value := strings.TrimSpace(strings.SplitN(line[marker+len("status: "):], ",", 2)[0])
			if value == "" {
				break
			}
			return value, setupCheck{Name: "全局拒绝递归效果", Status: "pass", Detail: "递归测试返回 RCODE=" + value + "，测试名=" + name}
		}
	}
	return "", setupCheck{Name: "全局拒绝递归效果", Status: "fail", Detail: "递归响应缺少有效 RCODE"}
}

func splitDNSAddress(address string) (string, string) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return strings.Trim(strings.TrimSpace(address), "[]"), "53"
	}
	return strings.Trim(host, "[]"), port
}

func setupTSIGProbe(ctx context.Context, request setupRequest) setupCheck {
	host, port := splitDNSAddress(request.Primary.Address)
	buffer := make([]byte, 6)
	if _, err := rand.Read(buffer); err != nil {
		return setupCheck{Name: "TSIG 动态更新权限", Status: "fail", Detail: "无法生成受控测试记录名"}
	}
	probe := "_dnsguard-bootstrap-" + hex.EncodeToString(buffer) + "." + request.Zone
	addInput := fmt.Sprintf("server %s %s\nzone %s\nupdate add %s 30 TXT \"dnsguard-setup-probe\"\nsend\n", host, port, request.Zone, probe)
	if err := runSetupNSUpdate(ctx, request.TSIGKeyPath, addInput); err != nil {
		return setupCheck{Name: "TSIG 动态更新权限", Status: "fail", Detail: "受控 TXT 写入失败；只读检查不能证明 TSIG 写权限", Impact: "本次验证尝试向 Primary Zone 写入临时 TXT", Cleanup: "未确认写入成功，需人工核对该临时记录"}
	}
	cleanup := fmt.Sprintf("server %s %s\nzone %s\nupdate delete %s TXT\nsend\n", host, port, request.Zone, probe)
	if err := runSetupNSUpdate(ctx, request.TSIGKeyPath, cleanup); err != nil {
		return setupCheck{Name: "TSIG 动态更新权限", Status: "fail", Detail: "写入成功但临时 TXT 清理失败；禁止继续初始化", Impact: "Primary 可能仍保留临时 TXT", Cleanup: "请人工删除临时记录 " + probe}
	}
	return setupCheck{Name: "TSIG 动态更新权限", Status: "pass", Detail: "受控 TXT 写入和清理均成功，TSIG 动态更新权限已验证", Impact: "验证期间曾向 Primary Zone 写入临时 TXT", Cleanup: "临时 TXT 已删除"}
}

func runSetupNSUpdate(parent context.Context, keyPath, input string) error {
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "nsupdate", "-k", keyPath)
	command.Stdin = strings.NewReader(input)
	if err := command.Run(); err != nil {
		return fmt.Errorf("nsupdate failed")
	}
	return nil
}
