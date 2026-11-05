package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeDigRequiringNoRecurse(t *testing.T, dir string) {
	t.Helper()
	digPath := filepath.Join(dir, "dig")
	script := `#!/bin/sh
found=0
soa=0
for arg in "$@"; do
  [ "$arg" = "+norecurse" ] && found=1
  [ "$arg" = "SOA" ] && soa=1
done
[ "$found" -eq 1 ] || { echo "missing +norecurse" >&2; exit 7; }
if [ "$soa" -eq 1 ]; then
  printf '%s\n' 'ns.example. hostmaster.example. 42 3600 900 2592000 60'
else
  printf '%s\n' 'rpz-passthru.'
fi
`
	if err := os.WriteFile(digPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestAuthoritativeRPZQueriesUseNoRecurse(t *testing.T) {
	setupTestEnvironment(t)
	binDir := t.TempDir()
	writeDigRequiringNoRecurse(t, binDir)

	serial, err := probeDNSZone(context.Background(), "127.0.0.1:53", "rpz.local")
	if err != nil || serial != "42" {
		t.Fatalf("authoritative SOA probe failed: serial=%q err=%v", serial, err)
	}
	answers, err := queryDNSNode(context.Background(), "127.0.0.1:53", "example.rpz.local.", "CNAME")
	if err != nil || len(answers) != 1 || answers[0] != "rpz-passthru." {
		t.Fatalf("authoritative RPZ record probe failed: answers=%v err=%v", answers, err)
	}
}

func TestDNSNodeCannotDeletePrimary(t *testing.T) {
	original := state
	defer func() { state = original }()
	state = dnsState{Nodes: []DNSNode{
		{ID: "primary-1", Role: "主节点", Address: "127.0.0.2:5353"},
		{ID: "secondary-1", Role: "辅节点", Address: "127.0.0.3:5353"},
	}}
	request := httptest.NewRequest(http.MethodDelete, "/api/dns/nodes/primary-1", nil)
	recorder := httptest.NewRecorder()
	dnsNodeByID(recorder, request)
	if recorder.Code != http.StatusConflict || len(state.Nodes) != 2 {
		t.Fatalf("primary deletion should be rejected, status=%d nodes=%d", recorder.Code, len(state.Nodes))
	}
}

func TestDNSHealthRecordsLastChecked(t *testing.T) {
	originalState := state
	originalCache := dnsHealthCache
	originalAt := dnsHealthAt
	defer func() {
		state = originalState
		dnsHealthCache = originalCache
		dnsHealthAt = originalAt
	}()
	state = dnsState{Nodes: []DNSNode{{ID: "health-test", Role: "辅节点", Address: "127.0.0.1:1"}}}
	dnsHealthCache = nil
	dnsHealthAt = time.Time{}
	refreshDNSHealth()
	if len(dnsHealthCache) != 1 {
		t.Fatalf("expected one health result, got %d", len(dnsHealthCache))
	}
	if _, err := time.Parse("2006-01-02 15:04:05", dnsHealthCache[0].LastChecked); err != nil {
		t.Fatalf("last checked time should use the local display format, got %q: %v", dnsHealthCache[0].LastChecked, err)
	}
}

func TestRPZRuleUpdateChangesTargetAndRequiresPublish(t *testing.T) {
	t.Setenv("DNS_STATE_FILE", filepath.Join(t.TempDir(), "dns-state.json"))
	t.Setenv("AUDIT_FILE", filepath.Join(t.TempDir(), "audit.json"))
	original := state
	defer func() { state = original }()
	state = dnsState{Rules: []RPZRule{{ID: "rule-1", Domain: "old.example.com", Action: "passthru", Type: "CNAME", Reason: "old", Status: "published", UpdatedAt: "2026-01-01T00:00:00Z"}}}
	request := httptest.NewRequest(http.MethodPut, "/api/dns/rpz/rule-1", strings.NewReader(`{"domain":"new.example.com","type":"A","value":"192.0.2.20","reason":"updated"}`))
	request.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	dnsRuleByID(recorder, request)
	if recorder.Code != http.StatusOK || state.Rules[0].Domain != "new.example.com" || state.Rules[0].Type != "A" || state.Rules[0].Value != "192.0.2.20" || state.Rules[0].Status != "draft" {
		t.Fatalf("rule update failed: status=%d rule=%+v", recorder.Code, state.Rules[0])
	}
}

func TestRPZRuleCreateRollsBackWhenStateWriteFails(t *testing.T) {
	t.Setenv("DNS_STATE_FILE", "/dev/null/dns-state.json")
	original := state
	defer func() { state = original }()
	state = dnsState{}
	request := httptest.NewRequest(http.MethodPost, "/api/dns/rpz", strings.NewReader(`{"domain":"write-failure.example.com","reason":"test"}`))
	request.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	dnsRules(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected state write failure, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(state.Rules) != 0 {
		t.Fatalf("failed create must not remain in memory: %+v", state.Rules)
	}
}

func TestRPZRuleDeleteRollsBackWhenStateWriteFails(t *testing.T) {
	t.Setenv("DNS_STATE_FILE", "/dev/null/dns-state.json")
	original := state
	defer func() { state = original }()
	state = dnsState{Rules: []RPZRule{{ID: "rule-1", Domain: "delete-failure.example.com", Action: "passthru", Type: "CNAME"}}}
	request := httptest.NewRequest(http.MethodDelete, "/api/dns/rpz/rule-1", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	dnsRuleByID(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected state write failure, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(state.Rules) != 1 || state.Rules[0].ID != "rule-1" {
		t.Fatalf("failed delete must restore the rule: %+v", state.Rules)
	}
}

func TestCompileRPZIncludesExactAndWildcardTriggers(t *testing.T) {
	t.Setenv("RPZ_ZONE", "rpz.local")
	content, err := compileRPZ([]RPZRule{{Domain: "baidu.com", Reason: "test"}})
	if err != nil {
		t.Fatalf("compileRPZ returned error: %v", err)
	}
	for _, trigger := range []string{"baidu.com.rpz.local.", "*.baidu.com.rpz.local."} {
		if !strings.Contains(content, trigger+" 60 CNAME rpz-passthru.") {
			t.Fatalf("missing trigger %q in RPZ output:\n%s", trigger, content)
		}
	}
}

func TestCompileRPZSupportsARecordRedirect(t *testing.T) {
	t.Setenv("RPZ_ZONE", "rpz.local")
	content, err := compileRPZ([]RPZRule{{Type: "A", Domain: "example.com", Value: "192.0.2.10", Reason: "test redirect"}})
	if err != nil {
		t.Fatalf("compileRPZ returned error: %v", err)
	}
	for _, trigger := range []string{"example.com.rpz.local.", "*.example.com.rpz.local."} {
		if !strings.Contains(content, trigger+" 60 A 192.0.2.10") {
			t.Fatalf("missing A trigger %q in RPZ output:\n%s", trigger, content)
		}
	}
	if _, err := compileRPZ([]RPZRule{{Type: "A", Domain: "example.com", Value: "not-an-ip", Reason: "invalid"}}); err == nil {
		t.Fatal("invalid A address should fail RPZ compilation")
	}
}

func TestRPZRulesEqualIgnoresRuntimeStatus(t *testing.T) {
	current := []RPZRule{{ID: "current", Domain: "example.com", Action: "passthru", Type: "CNAME", Reason: "approved", Status: "published"}}
	published := []RPZRule{{ID: "published", Domain: "example.com", Action: "passthru", Reason: "approved", Status: "draft"}}
	if !rpzRulesEqual(current, published) {
		t.Fatal("equivalent rules with different runtime status should compare equal")
	}
	published[0].Reason = "changed"
	if rpzRulesEqual(current, published) {
		t.Fatal("changed rule reason should require a new publish")
	}
	published[0].Reason = "approved"
	published[0].Type = "A"
	published[0].Value = "192.0.2.10"
	if rpzRulesEqual(current, published) {
		t.Fatal("changed rule type/value should require a new publish")
	}
}

func TestRPZHitCountReadsConfiguredBINDLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rpz.log")
	content := "one rpz QNAME NXDOMAIN rewrite\nplain query\ntwo rpz IP DROP rewrite\n"
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RPZ_LOG_FILES", path)
	count, ready := rpzHitCount()
	if !ready || count != 2 {
		t.Fatalf("expected 2 RPZ hits from configured log, got count=%d ready=%v", count, ready)
	}
}

func TestRPZHitCountReportsNotConfigured(t *testing.T) {
	t.Setenv("RPZ_LOG_FILES", "")
	count, ready := rpzHitCount()
	if ready || count != 0 {
		t.Fatalf("expected not-configured result, got count=%d ready=%v", count, ready)
	}
}

func TestRPZHitFingerprintDeduplicatesNodesWithinWindow(t *testing.T) {
	lines := []string{
		"03-Nov-2026 15:37:12.073 client @a 127.0.0.1#41169 (hit-test.example): rpz QNAME NXDOMAIN rewrite hit-test.example/A/IN via hit-test.example.rpz.local",
		"03-Nov-2026 15:37:12.101 client @b 127.0.0.1#36679 (hit-test.example): rpz QNAME NXDOMAIN rewrite hit-test.example/A/IN via hit-test.example.rpz.local",
	}
	first, ok := rpzHitFingerprint(lines[0], 2)
	second, ok2 := rpzHitFingerprint(lines[1], 2)
	if !ok || !ok2 || first != second {
		t.Fatalf("expected matching fingerprints, got %q/%q (%v/%v)", first, second, ok, ok2)
	}
}

func TestNextRuleIDIsUnique(t *testing.T) {
	first := nextRuleID()
	second := nextRuleID()
	if first == second || first == "" || second == "" {
		t.Fatalf("rule IDs are not unique: %q and %q", first, second)
	}
}

func TestSaveDNSStateCreatesAtomicBackup(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dns-state.json")
	t.Setenv("DNS_STATE_FILE", statePath)
	original := state
	defer func() { state = original }()
	state = dnsState{Nodes: []DNSNode{{ID: "test"}}, Rules: []RPZRule{}, Published: []RPZRule{}}
	if err := saveDNSState(); err != nil {
		t.Fatal(err)
	}
	state.Nodes[0].Name = "updated"
	if err := saveDNSState(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath + ".bak"); err != nil {
		t.Fatalf("expected backup file: %v", err)
	}
	backup, err := os.ReadFile(statePath + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	var restored dnsState
	if err := json.Unmarshal(backup, &restored); err != nil {
		t.Fatalf("backup is not valid JSON: %v", err)
	}
	if restored.Nodes[0].Name != "" {
		t.Fatalf("backup should contain the previous version, got %+v", restored.Nodes[0])
	}
}

func TestSaveDNSStateFailsClosedWhenBackupCannotBeWritten(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dns-state.json")
	t.Setenv("DNS_STATE_FILE", statePath)
	original := state
	defer func() { state = original }()
	state = dnsState{Rules: []RPZRule{{Domain: "old.example.com"}}}
	if err := os.WriteFile(statePath, []byte(`{"rules":[{"domain":"old.example.com"}]}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath+".bak", 0o750); err != nil {
		t.Fatal(err)
	}
	state.Rules[0].Domain = "new.example.com"
	if err := saveDNSState(); err == nil {
		t.Fatal("save should fail when the backup path cannot be written")
	}
	content, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "new.example.com") {
		t.Fatalf("main state must not be replaced after backup failure: %s", content)
	}
}

func TestLoadDNSStateFailsClosedWhenMainAndBackupAreCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-state.json")
	t.Setenv("DNS_STATE_FILE", path)
	if err := os.WriteFile(path, []byte("{not-json"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", []byte("also-not-json"), 0o640); err != nil {
		t.Fatal(err)
	}
	original := state
	defer func() { state = original }()
	state = dnsState{Rules: []RPZRule{{Domain: "must-remain.example.com"}}}
	if err := loadDNSState(); err == nil {
		t.Fatal("corrupt state and backup must fail closed")
	}
	if len(state.Rules) != 1 || state.Rules[0].Domain != "must-remain.example.com" {
		t.Fatalf("failed load must not replace in-memory state: %+v", state)
	}
}

func TestDNSNodeConfigRoundTrip(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "dns-nodes.json")
	t.Setenv("DNS_NODE_CONFIG_FILE", configPath)
	original := state
	defer func() { state = original }()
	state = dnsState{Nodes: []DNSNode{{ID: "primary-1", Name: "Primary", Role: "primary", Address: "127.0.0.2:5353"}}}
	if err := saveDNSNodeConfig(); err != nil {
		t.Fatal(err)
	}
	state.Nodes[0].Address = "127.0.0.9:5353"
	if err := loadDNSNodeConfig(); err != nil {
		t.Fatal(err)
	}
	if got := state.Nodes[0].Address; got != "127.0.0.2:5353" {
		t.Fatalf("expected address from config file, got %q", got)
	}
}

func TestCaptchaSVGDoesNotExposePlaintextCode(t *testing.T) {
	code := "A7K4"
	svg := captchaSVG(code)
	if strings.Contains(svg, "<text") || strings.Contains(svg, code) {
		t.Fatalf("captcha SVG exposes plaintext code: %s", svg)
	}
}

func TestCaptchaRateLimit(t *testing.T) {
	const ip = "198.51.100.77:40000"
	captchaRateMu.Lock()
	delete(captchaRates, "198.51.100.77")
	captchaRateMu.Unlock()
	for attempt := 1; attempt <= captchaRateLimit; attempt++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/api/auth/captcha", nil)
		request.RemoteAddr = ip
		captcha(recorder, request)
		if recorder.Code != 200 {
			t.Fatalf("request %d unexpectedly returned %d", attempt, recorder.Code)
		}
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/auth/captcha", nil)
	request.RemoteAddr = ip
	captcha(recorder, request)
	if recorder.Code != 429 {
		t.Fatalf("expected rate limit response 429, got %d", recorder.Code)
	}
}

func TestDNSNodeAddressAllowlist(t *testing.T) {
	t.Setenv("DNS_NODE_ALLOWED_CIDRS", "192.0.2.0/24,127.0.0.0/8")
	t.Setenv("DNS_NODE_ALLOWED_HOSTS", "dns-primary.internal")
	for _, test := range []struct {
		address string
		allowed bool
	}{
		{"192.0.2.10:53", true},
		{"127.0.0.2:5353", true},
		{"203.0.113.10:53", false},
		{"dns-primary.internal:53", true},
		{"other.internal:53", false},
	} {
		if got := dnsNodeAddressAllowed(test.address); got != test.allowed {
			t.Errorf("dnsNodeAddressAllowed(%q) = %v, want %v", test.address, got, test.allowed)
		}
	}
}

func TestValidateDNSNodeSetRequiresOnePrimaryAndKnownRoles(t *testing.T) {
	base := []DNSNode{
		{ID: "primary", Name: "Primary", Role: "primary", Address: "127.0.0.2:5353"},
		{ID: "secondary", Name: "Secondary", Role: "secondary", Address: "127.0.0.3:5353"},
	}
	if err := validateDNSNodeSet(base); err != nil {
		t.Fatalf("valid node set rejected: %v", err)
	}
	base[1].Role = "other"
	if err := validateDNSNodeSet(base); err == nil {
		t.Fatal("unknown node role must be rejected")
	}
	base[1].Role = "primary"
	if err := validateDNSNodeSet(base); err == nil {
		t.Fatal("multiple primary nodes must be rejected")
	}
}

func TestRPZHitCountReadsBoundedLogTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named.log")
	old := "01-Jan-2026 00:00:00.000 client 192.0.2.1#1234 (old.example.com): rpz QNAME NXDOMAIN\n"
	if err := os.WriteFile(path, []byte(old+strings.Repeat("x", 70*1024)), 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RPZ_LOG_FILES", path)
	t.Setenv("RPZ_LOG_MAX_BYTES", "65536")
	if count, readable := rpzHitCount(); !readable || count != 0 {
		t.Fatalf("expected only bounded tail to be read, count=%d readable=%v", count, readable)
	}
}

func TestLiveDNSNodesReturnsFreshCacheWithoutDig(t *testing.T) {
	t.Setenv("DNS_HEALTH_CACHE_SECONDS", "60")
	dnsHealthMu.Lock()
	originalCache := dnsHealthCache
	originalAt := dnsHealthAt
	dnsHealthCache = []DNSNode{{ID: "cached", Status: "healthy", RPZVersion: "42"}}
	dnsHealthAt = time.Now()
	dnsHealthMu.Unlock()
	defer func() {
		dnsHealthMu.Lock()
		dnsHealthCache = originalCache
		dnsHealthAt = originalAt
		dnsHealthMu.Unlock()
	}()

	started := time.Now()
	got := liveDNSNodes()
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("cached node read took %s; expected no synchronous dig", elapsed)
	}
	if len(got) != 1 || got[0].ID != "cached" {
		t.Fatalf("unexpected cached nodes: %+v", got)
	}
}
