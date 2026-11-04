package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func setupTestEnvironment(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AUTH_SECRET", "setup-test-secret-with-more-than-32-characters-2026")
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("DNS_NODE_ALLOWED_CIDRS", "127.0.0.0/8")
	t.Setenv("AUTH_FILE", filepath.Join(dir, "auth.json"))
	t.Setenv("DNS_NODE_CONFIG_FILE", filepath.Join(dir, "dns-nodes.json"))
	t.Setenv("DNS_STATE_FILE", filepath.Join(dir, "dns-state.json"))
	t.Setenv("AUDIT_FILE", filepath.Join(dir, "audit.json"))
	t.Setenv("INITIALIZATION_FILE", filepath.Join(dir, "initialization.json"))
	t.Setenv("BOOTSTRAP_TOKEN_FILE", filepath.Join(dir, "bootstrap.token"))
	t.Setenv("BOOTSTRAP_KEY_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.token"), []byte("setup-bootstrap-token-012345678901234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "rpz-manager.key")
	if err := os.WriteFile(key, []byte(`key "rpz-manager" { secret "test"; };`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RPZ_KEY_FILE", key)
	initialization = initializationState{}
	state = dnsState{}
	storedAuth = authStore{}
	auditEntries = nil
	setAuditIntegrityFailure(nil)
	t.Cleanup(func() {
		initialization = initializationState{}
		state = dnsState{}
		storedAuth = authStore{}
		auditEntries = nil
		setAuditIntegrityFailure(nil)
	})
	return dir, key
}

func readySetupChecks(context.Context, setupRequest) setupCheckResult {
	return setupCheckResult{Ready: true, Checks: []setupCheck{{Name: "test", Status: "pass", Detail: "injected"}}}
}

func validSetupRequest(key string) setupRequest {
	return setupRequest{
		Username:    "admin",
		Password:    "a-strong-setup-password",
		Zone:        "rpz.local",
		Primary:     setupNode{Address: "127.0.0.1:5353"},
		Secondaries: []setupNode{{Address: "127.0.0.1:5354"}},
		TSIGKeyPath: key,
		WriteTest:   true,
	}
}

func setupRequestBody(t *testing.T, request setupRequest) *bytes.Reader {
	t.Helper()
	content, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(content)
}

func TestSetupRejectsBadBootstrapTokenWithoutReturningExpectedToken(t *testing.T) {
	_, key := setupTestEnvironment(t)
	request := validSetupRequest(key)
	body := setupRequestBody(t, request)
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/setup/validate", body)
	httpRequest.Header.Set("X-DNSGuard-Bootstrap", "wrong-token")
	recorder := httptest.NewRecorder()
	setupValidate(recorder, httpRequest)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "setup-bootstrap-token") {
		t.Fatal("bootstrap token must never be returned")
	}
}

func TestSetupCompletesOnceAndRejectsRepeat(t *testing.T) {
	_, key := setupTestEnvironment(t)
	originalChecks := setupChecksFunc
	setupChecksFunc = readySetupChecks
	t.Cleanup(func() { setupChecksFunc = originalChecks })
	request := validSetupRequest(key)
	request.Username = "operator"
	first := httptest.NewRequest(http.MethodPost, "/api/setup/complete", setupRequestBody(t, request))
	first.Header.Set("X-DNSGuard-Bootstrap", "setup-bootstrap-token-012345678901234567890")
	recorder := httptest.NewRecorder()
	setupComplete(recorder, first)
	if recorder.Code != http.StatusOK {
		t.Fatalf("first setup failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if !isInitialized() {
		t.Fatal("setup must persist initialized state")
	}
	if authUsername() != "operator" || !passwordValid("operator", request.Password) {
		t.Fatal("configured administrator username/password must be usable after setup")
	}
	repeat := httptest.NewRequest(http.MethodPost, "/api/setup/complete", setupRequestBody(t, request))
	repeat.Header.Set("X-DNSGuard-Bootstrap", "setup-bootstrap-token-012345678901234567890")
	repeatRecorder := httptest.NewRecorder()
	setupComplete(repeatRecorder, repeat)
	if repeatRecorder.Code != http.StatusConflict {
		t.Fatalf("repeat setup must be rejected, got %d", repeatRecorder.Code)
	}
}

func TestSetupConcurrentCompletionHasOneWinner(t *testing.T) {
	_, key := setupTestEnvironment(t)
	originalChecks := setupChecksFunc
	setupChecksFunc = readySetupChecks
	t.Cleanup(func() { setupChecksFunc = originalChecks })
	request := validSetupRequest(key)
	results := make([]int, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			httpRequest := httptest.NewRequest(http.MethodPost, "/api/setup/complete", setupRequestBody(t, request))
			httpRequest.Header.Set("X-DNSGuard-Bootstrap", "setup-bootstrap-token-012345678901234567890")
			recorder := httptest.NewRecorder()
			setupComplete(recorder, httpRequest)
			results[index] = recorder.Code
		}(index)
	}
	wait.Wait()
	if !((results[0] == http.StatusOK && results[1] == http.StatusConflict) || (results[1] == http.StatusOK && results[0] == http.StatusConflict)) {
		t.Fatalf("expected one winner and one conflict, got %v", results)
	}
}

func TestInterruptedSetupIsRecoveredAsFailed(t *testing.T) {
	dir, key := setupTestEnvironment(t)
	originalChecks := setupChecksFunc
	setupChecksFunc = readySetupChecks
	t.Setenv("DNSGUARD_SETUP_FAIL_AFTER", "auth")
	t.Cleanup(func() { setupChecksFunc = originalChecks })
	request := validSetupRequest(key)
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/setup/complete", setupRequestBody(t, request))
	httpRequest.Header.Set("X-DNSGuard-Bootstrap", "setup-bootstrap-token-012345678901234567890")
	recorder := httptest.NewRecorder()
	setupComplete(recorder, httpRequest)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("injected interruption should fail, got %d", recorder.Code)
	}
	if regularFileExists(filepath.Join(dir, "auth.json")) {
		t.Fatal("interrupted setup must not leave administrator auth half-created")
	}
	if err := loadInitializationState(); err != nil {
		t.Fatal(err)
	}
	initializationMu.Lock()
	status := initialization.Status
	initializationMu.Unlock()
	if status != initializationFailed {
		t.Fatalf("expected failed recovery state, got %q", status)
	}
}

func TestSetupRejectsWorldReadableTSIGKey(t *testing.T) {
	dir, _ := setupTestEnvironment(t)
	path := filepath.Join(dir, "world-readable.key")
	if err := os.WriteFile(path, []byte("key"), 0o604); err != nil {
		t.Fatal(err)
	}
	if err := validateSetupKey(path); err == nil {
		t.Fatal("world-readable TSIG key must be rejected")
	}
}

func TestExistingDeploymentIsNotForcedThroughWizard(t *testing.T) {
	_, _ = setupTestEnvironment(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("existing-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("AUTH_FILE"), []byte(`{"username":"admin","passwordHash":"`+string(hash)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes := `[ {"id":"primary-1","name":"primary","role":"primary","address":"127.0.0.1:5353"}, {"id":"secondary-1","name":"secondary","role":"secondary","address":"127.0.0.1:5354"} ]`
	if err := os.WriteFile(os.Getenv("DNS_NODE_CONFIG_FILE"), []byte(nodes), 0o640); err != nil {
		t.Fatal(err)
	}
	if !isInitialized() {
		t.Fatal("valid existing auth and node files must count as initialized")
	}
	recorder := httptest.NewRecorder()
	setupStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/setup/status", nil))
	if !strings.Contains(recorder.Body.String(), `"initialized":true`) {
		t.Fatalf("existing deployment must not show first-run wizard: %s", recorder.Body.String())
	}
}

func TestInitializationMiddlewareLocksRPZPublish(t *testing.T) {
	setupTestEnvironment(t)
	t.Setenv("AUTH_ENABLED", "false")
	request := httptest.NewRequest(http.MethodPost, "/api/dns/rpz/publish", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	authMiddleware(http.HandlerFunc(publishRPZ)).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPreconditionRequired {
		t.Fatalf("uninitialized RPZ publish must be locked, got %d", recorder.Code)
	}
}
