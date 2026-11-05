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
	t.Setenv("APP_ENV", "production")
	request := httptest.NewRequest(http.MethodPost, "/api/dns/rpz/publish", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	authMiddleware(http.HandlerFunc(publishRPZ)).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPreconditionRequired {
		t.Fatalf("uninitialized RPZ publish must be locked, got %d", recorder.Code)
	}
}

func TestSetupImportsWhitelistSeedAsDraftOnly(t *testing.T) {
	dir, key := setupTestEnvironment(t)
	seedPath := filepath.Join(dir, "bootstrap", "whitelist.json")
	if err := os.MkdirAll(filepath.Dir(seedPath), 0o750); err != nil {
		t.Fatal(err)
	}
	seed := `{"version":1,"source":"rpz-connect","mode":"global","generatedAt":"2026-11-05T00:00:00Z","zone":"rpz.local.","rules":[{"domain":"Example.COM.","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"seed"},{"domain":"child.example.net","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"seed"}]}`
	if err := os.WriteFile(seedPath, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RPZ_WHITELIST_SEED_FILE", seedPath)
	originalChecks := setupChecksFunc
	setupChecksFunc = readySetupChecks
	t.Cleanup(func() { setupChecksFunc = originalChecks })
	request := validSetupRequest(key)
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/setup/complete", setupRequestBody(t, request))
	httpRequest.Header.Set("X-DNSGuard-Bootstrap", "setup-bootstrap-token-012345678901234567890")
	recorder := httptest.NewRecorder()
	setupComplete(recorder, httpRequest)
	if recorder.Code != http.StatusOK {
		t.Fatalf("setup with whitelist seed failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if len(state.Rules) != 2 || len(state.Published) != 0 {
		t.Fatalf("seed rules must be imported as unpublished drafts: rules=%d published=%d", len(state.Rules), len(state.Published))
	}
	if state.Rules[0].Domain != "example.com" || state.Rules[0].Status != "draft" || state.Rules[0].Type != "CNAME" {
		t.Fatalf("seed rule was not normalized as a draft: %#v", state.Rules[0])
	}
}

func TestSetupRejectsInvalidWhitelistSeedBeforeWritingState(t *testing.T) {
	dir, key := setupTestEnvironment(t)
	seedPath := filepath.Join(dir, "bootstrap", "whitelist.json")
	if err := os.MkdirAll(filepath.Dir(seedPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seedPath, []byte(`{"version":1,"source":"rpz-connect","mode":"global","zone":"rpz.local.","rules":[{"domain":"bad_domain.example","action":"passthru","type":"CNAME"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RPZ_WHITELIST_SEED_FILE", seedPath)
	originalChecks := setupChecksFunc
	setupChecksFunc = readySetupChecks
	t.Cleanup(func() { setupChecksFunc = originalChecks })
	request := validSetupRequest(key)
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/setup/complete", setupRequestBody(t, request))
	httpRequest.Header.Set("X-DNSGuard-Bootstrap", "setup-bootstrap-token-012345678901234567890")
	recorder := httptest.NewRecorder()
	setupComplete(recorder, httpRequest)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid seed must be rejected, got %d %s", recorder.Code, recorder.Body.String())
	}
	if regularFileExists(os.Getenv("AUTH_FILE")) || regularFileExists(os.Getenv("DNS_STATE_FILE")) {
		t.Fatal("invalid seed must not create authentication or DNS state")
	}
}

func TestGlobalPolicyModeRequiresWhitelistSeed(t *testing.T) {
	setupTestEnvironment(t)
	t.Setenv("RPZ_DEFAULT_DENY_MODE", "global")
	if _, err := loadWhitelistSeedForZone("rpz.local"); err == nil {
		t.Fatal("global policy mode must require a reviewed whitelist seed")
	}
}

func TestGlobalPolicyModePersistsWithImportedDrafts(t *testing.T) {
	dir, key := setupTestEnvironment(t)
	t.Setenv("RPZ_DEFAULT_DENY_MODE", "global")
	seedPath := filepath.Join(dir, "bootstrap", "whitelist.json")
	if err := os.MkdirAll(filepath.Dir(seedPath), 0o750); err != nil {
		t.Fatal(err)
	}
	seed := `{"version":1,"source":"rpz-connect","mode":"global","generatedAt":"2026-11-05T00:00:00Z","zone":"rpz.local.","rules":[{"domain":"example.com","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"seed"}]}`
	if err := os.WriteFile(seedPath, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RPZ_WHITELIST_SEED_FILE", seedPath)
	originalChecks := setupChecksFunc
	setupChecksFunc = readySetupChecks
	t.Cleanup(func() { setupChecksFunc = originalChecks })
	request := validSetupRequest(key)
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/setup/complete", setupRequestBody(t, request))
	httpRequest.Header.Set("X-DNSGuard-Bootstrap", "setup-bootstrap-token-012345678901234567890")
	recorder := httptest.NewRecorder()
	setupComplete(recorder, httpRequest)
	if recorder.Code != http.StatusOK {
		t.Fatalf("global setup failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if state.PolicyMode != "global" || initialization.PolicyMode != "global" {
		t.Fatalf("global policy mode was not persisted: state=%q initialization=%q", state.PolicyMode, initialization.PolicyMode)
	}
}

func writeInitializedPolicyState(t *testing.T, policyMode string, includePolicyMode bool) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("existing-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("AUTH_FILE"), []byte(`{"username":"admin","passwordHash":"`+string(hash)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("DNS_NODE_CONFIG_FILE"), []byte(`[{"id":"primary-1","name":"primary","role":"primary","address":"127.0.0.1:5353"}]`), 0o640); err != nil {
		t.Fatal(err)
	}
	content := `{"nodes":[],"rules":[{"id":"rule-1","domain":"example.com","action":"passthru","type":"CNAME","value":"rpz-passthru.","reason":"existing","status":"published","updatedAt":"2026-11-05T00:00:00Z"}],"published":[],"versions":[]}`
	if includePolicyMode {
		content = strings.TrimSuffix(content, "}") + `,"policyMode":"` + policyMode + `"}`
	}
	if err := os.WriteFile(os.Getenv("DNS_STATE_FILE"), []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	initialization = initializationState{}
	if err := loadDNSState(); err != nil {
		t.Fatal(err)
	}
}

func TestHistoricalStateWithoutPolicyModeRemainsLegacy(t *testing.T) {
	setupTestEnvironment(t)
	writeInitializedPolicyState(t, "", false)
	t.Setenv("RPZ_DEFAULT_DENY_MODE", "legacy")
	if err := validatePolicyModeConsistency(); err != nil {
		t.Fatalf("historical legacy state should remain usable: %v", err)
	}
	if effectivePolicyMode() != "legacy" || state.PolicyMode != "" {
		t.Fatalf("historical state must remain legacy without being rewritten: effective=%q stored=%q", effectivePolicyMode(), state.PolicyMode)
	}
}

func TestHistoricalStateWithoutPolicyModeRejectsGlobalOptIn(t *testing.T) {
	setupTestEnvironment(t)
	writeInitializedPolicyState(t, "", false)
	t.Setenv("RPZ_DEFAULT_DENY_MODE", "global")
	if err := validatePolicyModeConsistency(); err == nil || !strings.Contains(err.Error(), "策略模式不一致") {
		t.Fatalf("historical state must reject an implicit global opt-in, got %v", err)
	}
	if effectivePolicyMode() != "legacy" || len(state.Rules) != 1 {
		t.Fatalf("historical state must remain legacy and preserve rules: effective=%q rules=%d", effectivePolicyMode(), len(state.Rules))
	}
}

func TestLegacyStateDoesNotSilentlySwitchToGlobal(t *testing.T) {
	setupTestEnvironment(t)
	writeInitializedPolicyState(t, "legacy", true)
	t.Setenv("RPZ_DEFAULT_DENY_MODE", "global")
	err := validatePolicyModeConsistency()
	if err == nil || !strings.Contains(err.Error(), "策略模式不一致") {
		t.Fatalf("legacy state must reject an unapproved global switch, got %v", err)
	}
	if effectivePolicyMode() != "legacy" || len(state.Rules) != 1 {
		t.Fatalf("conflict must preserve legacy state and rules: effective=%q rules=%d", effectivePolicyMode(), len(state.Rules))
	}
}

func TestGlobalStateDoesNotSilentlySwitchToLegacy(t *testing.T) {
	setupTestEnvironment(t)
	writeInitializedPolicyState(t, "global", true)
	t.Setenv("RPZ_DEFAULT_DENY_MODE", "legacy")
	err := validatePolicyModeConsistency()
	if err == nil || !strings.Contains(err.Error(), "策略模式不一致") {
		t.Fatalf("global state must reject an unapproved legacy switch, got %v", err)
	}
	if effectivePolicyMode() != "global" || len(state.Rules) != 1 {
		t.Fatalf("conflict must preserve global state and rules: effective=%q rules=%d", effectivePolicyMode(), len(state.Rules))
	}
}

func TestValidateGlobalDenyTriggerResponseRequiresStrictAuthoritativeRecord(t *testing.T) {
	const owner = "*.global-deny.rpz.local."
	valid := `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; flags: qr aa;
;; ANSWER SECTION:
*.global-deny.rpz.local. 60 IN CNAME .
;; AUTHORITY SECTION:`
	cases := []struct {
		name   string
		output string
		valid  bool
	}{
		{"authoritative exact CNAME root", valid, true},
		{"non-authoritative", strings.Replace(valid, "qr aa", "qr ra", 1), false},
		{"wrong RCODE", strings.Replace(valid, "NOERROR", "SERVFAIL", 1), false},
		{"wrong owner", strings.Replace(valid, owner, "other.global-deny.rpz.local.", 1), false},
		{"wrong type", strings.Replace(valid, "CNAME .", "A 192.0.2.1", 1), false},
		{"wrong target", strings.Replace(valid, "CNAME .", "CNAME sink.example.", 1), false},
		{"missing answer", strings.Replace(valid, "*.global-deny.rpz.local. 60 IN CNAME .\n", "", 1), false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := validateGlobalDenyTriggerResponse(test.output, owner)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
		})
	}
}
