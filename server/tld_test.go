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

func TestCompileTLDPolicyIncludesExactAndWildcardDenyTriggers(t *testing.T) {
	t.Setenv("TLD_DENY_ZONE", "tld-deny.rpz.local")
	t.Setenv("TLD_DENY_TTL_SECONDS", "60")
	content, err := compileTLDPolicy([]string{"COM", "net"})
	if err != nil {
		t.Fatalf("compileTLDPolicy returned error: %v", err)
	}
	for _, wanted := range []string{
		"com.tld-deny.rpz.local. 60 CNAME .",
		"*.com.tld-deny.rpz.local. 60 CNAME .",
		"net.tld-deny.rpz.local. 60 CNAME .",
		"*.net.tld-deny.rpz.local. 60 CNAME .",
	} {
		if !strings.Contains(content, wanted) {
			t.Fatalf("compiled TLD policy missing %q:\n%s", wanted, content)
		}
	}
}

func TestTLDSetDiffOnlyReturnsChangedEntries(t *testing.T) {
	adds, removes, err := tldSetDiff([]string{"COM", "ORG"}, []string{"COM", "NET"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(adds, ",") != "ORG" || strings.Join(removes, ",") != "NET" {
		t.Fatalf("unexpected TLD diff: adds=%v removes=%v", adds, removes)
	}
	adds, removes, err = tldSetDiff([]string{"COM"}, []string{"COM"})
	if err != nil || len(adds) != 0 || len(removes) != 0 {
		t.Fatalf("identical lists must produce no updates: adds=%v removes=%v err=%v", adds, removes, err)
	}
}

func TestParseTLDPolicyAXFRRequiresExactAndWildcardTriggers(t *testing.T) {
	content := "com.deny.rpz.local. 60 IN CNAME .\n*.com.deny.rpz.local. 60 IN CNAME .\nnet.deny.rpz.local. 60 IN CNAME .\n*.net.deny.rpz.local. 60 IN CNAME .\n"
	entries, err := parseTLDPolicyAXFR(content, "deny.rpz.local")
	if err != nil || strings.Join(entries, ",") != "COM,NET" {
		t.Fatalf("unexpected AXFR entries: entries=%v err=%v", entries, err)
	}
	if _, err := parseTLDPolicyAXFR("com.deny.rpz.local. 60 IN CNAME .\n", "deny.rpz.local"); err == nil {
		t.Fatal("incomplete exact/wildcard pair should be rejected")
	}
}

func TestRunTLDNSUpdateUsesIncrementalBatches(t *testing.T) {
	runtime := t.TempDir()
	keyPath := filepath.Join(runtime, "rpz.key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(runtime, "nsupdate.log")
	binDir := filepath.Join(runtime, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "nsupdate"), []byte("#!/bin/sh\ncat >> '"+logPath+"'\nprintf '\\n---BATCH---\\n' >> '"+logPath+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RPZ_PRIMARY", "127.0.0.1")
	t.Setenv("RPZ_PRIMARY_PORT", "5353")
	t.Setenv("RPZ_KEY_FILE", keyPath)
	t.Setenv("TLD_DENY_ZONE", "deny.rpz.local")
	t.Setenv("TLD_PUBLISH_BATCH_TLDS", "1")
	t.Setenv("TLD_PUBLISH_BATCH_BYTES", "4096")
	if err := runTLDNSUpdate(context.Background(), []string{"COM", "ORG"}, []string{"COM", "NET"}); err != nil {
		t.Fatalf("runTLDNSUpdate returned error: %v", err)
	}
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if strings.Contains(text, "com.deny.rpz.local") || !strings.Contains(text, "org.deny.rpz.local") || !strings.Contains(text, "net.deny.rpz.local") {
		t.Fatalf("incremental update contained wrong records: %s", text)
	}
	if strings.Count(text, "---BATCH---") != 2 {
		t.Fatalf("expected one batch per changed TLD, got log=%s", text)
	}
}

func TestSyncTLDNowPublishesSeparateDenyPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# Version 9, Last Updated test\nCOM\nNET\n"))
	}))
	defer server.Close()
	runtime := t.TempDir()
	keyPath := filepath.Join(runtime, "rpz.key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(runtime, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	digPath := filepath.Join(binDir, "dig")
	if err := os.WriteFile(digPath, []byte("#!/bin/sh\nprintf '%s\\n' 'deny.rpz.local. hostmaster.local. 42 3600 900 2592000 60'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("APP_ENV", "development")
	t.Setenv("TLD_DENY_ENABLED", "true")
	t.Setenv("TLD_DENY_PUBLISH_ENABLED", "true")
	t.Setenv("TLD_SOURCE_URL", server.URL)
	t.Setenv("TLD_STATE_FILE", filepath.Join(runtime, "tld-state.json"))
	t.Setenv("TLD_DENY_ARTIFACT_FILE", filepath.Join(runtime, "deny.rpz.local.db"))
	t.Setenv("TLD_DENY_ZONE", "deny.rpz.local")
	t.Setenv("TLD_DENY_TTL_SECONDS", "60")
	t.Setenv("RPZ_PRIMARY", "127.0.0.1")
	t.Setenv("RPZ_PRIMARY_PORT", "53")
	t.Setenv("RPZ_KEY_FILE", keyPath)
	previousState := tldStatusSnapshot()
	previousUpdate := runTLDNSUpdateFunc
	previousVerify := verifyTLDPolicyFunc
	defer func() {
		setTLDStatus(previousState)
		runTLDNSUpdateFunc = previousUpdate
		verifyTLDPolicyFunc = previousVerify
	}()
	var publishedCurrent, publishedPrevious []string
	runTLDNSUpdateFunc = func(_ context.Context, current, previous []string) error {
		publishedCurrent = append([]string(nil), current...)
		publishedPrevious = append([]string(nil), previous...)
		return nil
	}
	verifyTLDPolicyFunc = func(context.Context, []string) (tldPolicyVerification, error) {
		return tldPolicyVerification{PrimarySerial: "42", ZoneStatus: "published", SecondaryStatus: "synced", RecursionStatus: "not_configured", Representative: "com.deny.rpz.local."}, nil
	}
	setTLDStatus(TLDStatus{Status: "pending", Source: server.URL})
	if err := syncTLDNow(context.Background()); err != nil {
		t.Fatalf("syncTLDNow returned error: %v", err)
	}
	status := tldStatusSnapshot()
	if status.PolicyStatus != "published" || status.PolicySerial != "42" || status.TLDCount != 2 {
		t.Fatalf("unexpected published policy status: %+v", status)
	}
	if strings.Join(publishedCurrent, ",") != "COM,NET" || len(publishedPrevious) != 0 {
		t.Fatalf("unexpected update entries: current=%v previous=%v", publishedCurrent, publishedPrevious)
	}
	artifact, err := os.ReadFile(filepath.Join(runtime, "deny.rpz.local.db"))
	if err != nil || !strings.Contains(string(artifact), "*.com.deny.rpz.local. 60 CNAME .") {
		t.Fatalf("TLD deny artifact missing or invalid: err=%v content=%s", err, artifact)
	}
}

func TestSyncTLDNowDoesNotRepublishUnchangedPolicyWithoutHTTPValidators(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# Version 9, Last Updated test\nCOM\nNET\n"))
	}))
	defer server.Close()
	runtime := t.TempDir()
	keyPath := filepath.Join(runtime, "rpz.key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(runtime, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "dig"), []byte("#!/bin/sh\nprintf '%s\\n' 'deny.rpz.local. hostmaster.local. 42 3600 900 2592000 60'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("APP_ENV", "development")
	t.Setenv("TLD_DENY_ENABLED", "true")
	t.Setenv("TLD_DENY_PUBLISH_ENABLED", "true")
	t.Setenv("TLD_SOURCE_URL", server.URL)
	t.Setenv("TLD_STATE_FILE", filepath.Join(runtime, "tld-state.json"))
	t.Setenv("TLD_DENY_ARTIFACT_FILE", filepath.Join(runtime, "deny.rpz.local.db"))
	t.Setenv("TLD_DENY_ZONE", "deny.rpz.local")
	t.Setenv("RPZ_PRIMARY", "127.0.0.1")
	t.Setenv("RPZ_PRIMARY_PORT", "53")
	t.Setenv("RPZ_KEY_FILE", keyPath)
	previousState := tldStatusSnapshot()
	previousUpdate := runTLDNSUpdateFunc
	previousVerify := verifyTLDPolicyFunc
	defer func() {
		setTLDStatus(previousState)
		runTLDNSUpdateFunc = previousUpdate
		verifyTLDPolicyFunc = previousVerify
	}()
	updateCalls := 0
	runTLDNSUpdateFunc = func(_ context.Context, _, _ []string) error {
		updateCalls++
		return nil
	}
	verifyTLDPolicyFunc = func(context.Context, []string) (tldPolicyVerification, error) {
		return tldPolicyVerification{PrimarySerial: "42", ZoneStatus: "published", SecondaryStatus: "synced", RecursionStatus: "not_configured", Representative: "com.deny.rpz.local."}, nil
	}
	setTLDStatus(TLDStatus{Status: "pending", Source: server.URL})
	if err := syncTLDNow(context.Background()); err != nil {
		t.Fatalf("first syncTLDNow returned error: %v", err)
	}
	if err := syncTLDNow(context.Background()); err != nil {
		t.Fatalf("second syncTLDNow returned error: %v", err)
	}
	if updateCalls != 1 {
		t.Fatalf("unchanged policy should be published once, got %d calls", updateCalls)
	}
}

func TestSyncTLDNowDoesNotAutoReplayReconcileRequiredPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# Version 9, Last Updated test\nCOM\nNET\n"))
	}))
	defer server.Close()
	runtime := t.TempDir()
	statePath := filepath.Join(runtime, "tld-state.json")
	t.Setenv("APP_ENV", "development")
	t.Setenv("TLD_DENY_ENABLED", "true")
	t.Setenv("TLD_DENY_PUBLISH_ENABLED", "true")
	t.Setenv("TLD_SOURCE_URL", server.URL)
	t.Setenv("TLD_STATE_FILE", statePath)
	t.Setenv("TLD_DENY_ZONE", "deny.rpz.local")
	previousState := tldStatusSnapshot()
	previousUpdate := runTLDNSUpdateFunc
	defer func() {
		setTLDStatus(previousState)
		runTLDNSUpdateFunc = previousUpdate
	}()
	updateCalls := 0
	runTLDNSUpdateFunc = func(_ context.Context, _, _ []string) error {
		updateCalls++
		return nil
	}
	setTLDStatus(TLDStatus{
		Status:              "ready",
		Source:              server.URL,
		SHA256:              "old-digest",
		PolicyStatus:        "reconcile_required",
		PolicySerial:        "42",
		PolicyLastPublished: "2026-11-04T00:00:00Z",
		TLDs:                []string{"COM", "NET"},
	})
	if err := saveTLDState(tldStatusSnapshot()); err != nil {
		t.Fatalf("saveTLDState returned error: %v", err)
	}
	if err := syncTLDNow(context.Background()); err != nil {
		t.Fatalf("reconcile-required sync should not invoke a new publish: %v", err)
	}
	status := tldStatusSnapshot()
	if status.PolicyStatus != "reconcile_required" || updateCalls != 0 {
		t.Fatalf("reconcile-required policy was replayed or changed: status=%+v calls=%d", status, updateCalls)
	}
}

func TestParseTLDDocumentValidatesHeaderAndEntries(t *testing.T) {
	version, updated, digest, count, err := parseTLDDocument([]byte("# Version 2026110304, Last Updated Wed Nov 4 07:07:01 2026 UTC\nCOM\nCN\nXN--VERMGENSBERATER-CTB\n"))
	if err != nil {
		t.Fatalf("parseTLDDocument returned error: %v", err)
	}
	if version != "2026110304" || updated == "" || len(digest) != 64 || count != 3 {
		t.Fatalf("unexpected parsed metadata: version=%q updated=%q digest=%q count=%d", version, updated, digest, count)
	}
	if _, _, _, _, err := parseTLDDocument([]byte("# Version 1, Last Updated now\nCOM\nCOM\n")); err == nil {
		t.Fatal("duplicate TLD entry should be rejected")
	}
	if _, _, _, _, err := parseTLDDocument([]byte("COM\n")); err == nil {
		t.Fatal("missing version header should be rejected")
	}
}

func TestValidateTLDCountChange(t *testing.T) {
	previous := TLDStatus{TLDCount: 1436, TLDs: []string{"COM"}}
	if err := validateTLDCountChange(previous, 1300); err != nil {
		t.Fatalf("normal relative decrease should be accepted: %v", err)
	}
	if err := validateTLDCountChange(previous, 1290); err == nil {
		t.Fatal("decrease greater than ten percent should be rejected")
	}
	if err := validateTLDCountChange(TLDStatus{}, 1); err != nil {
		t.Fatalf("first sync should not use a previous-list threshold: %v", err)
	}
}

func TestPublishTLDPolicyTimeoutRequiresReconciliation(t *testing.T) {
	runtime := t.TempDir()
	t.Setenv("TLD_DENY_ZONE", "deny.rpz.local")
	t.Setenv("TLD_DENY_ARTIFACT_FILE", filepath.Join(runtime, "deny.rpz.local.db"))
	binDir := filepath.Join(runtime, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "named-checkzone"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	previousUpdate := runTLDNSUpdateFunc
	defer func() { runTLDNSUpdateFunc = previousUpdate }()
	runTLDNSUpdateFunc = func(ctx context.Context, _, _ []string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	verification, err := publishTLDPolicy(ctx, []string{"COM"}, nil, "")
	if err == nil || verification.ZoneStatus != "reconcile_required" {
		t.Fatalf("timeout should require reconciliation: verification=%+v err=%v", verification, err)
	}
}

func TestReconcileTLDPolicyRequiresExactZoneSetBeforeRecovery(t *testing.T) {
	runtime := t.TempDir()
	t.Setenv("TLD_STATE_FILE", filepath.Join(runtime, "tld-state.json"))
	t.Setenv("AUDIT_FILE", filepath.Join(runtime, "audit.json"))
	t.Setenv("TLD_DENY_ZONE", "deny.rpz.local")
	previousState := tldStatusSnapshot()
	previousEntries := queryTLDEntriesFunc
	previousVerify := verifyTLDPolicyFunc
	previousAudit := auditEntries
	defer func() {
		setTLDStatus(previousState)
		queryTLDEntriesFunc = previousEntries
		verifyTLDPolicyFunc = previousVerify
		auditEntries = previousAudit
		setAuditIntegrityFailure(nil)
	}()
	auditEntries = nil
	setAuditIntegrityFailure(nil)
	setTLDStatus(TLDStatus{Status: "ready", PolicyStatus: "reconcile_required", TLDs: []string{"COM", "NET"}})
	queryTLDEntriesFunc = func(context.Context) ([]string, error) {
		return []string{"COM"}, nil
	}
	request := httptest.NewRequest(http.MethodPost, "/api/dns/tld/reconcile", strings.NewReader("{}"))
	recorder := httptest.NewRecorder()
	reconcileTLDPolicy(recorder, request)
	if recorder.Code != http.StatusConflict || tldStatusSnapshot().PolicyStatus != "reconcile_required" {
		t.Fatalf("mismatched AXFR set must remain locked: code=%d status=%+v", recorder.Code, tldStatusSnapshot())
	}
	queryTLDEntriesFunc = func(context.Context) ([]string, error) {
		return []string{"COM", "NET"}, nil
	}
	verifyTLDPolicyFunc = func(context.Context, []string) (tldPolicyVerification, error) {
		return tldPolicyVerification{PrimarySerial: "17", ZoneStatus: "published", SecondaryStatus: "synced", RecursionStatus: "not_configured", Representative: "com.deny.rpz.local."}, nil
	}
	recorder = httptest.NewRecorder()
	reconcileTLDPolicy(recorder, request)
	status := tldStatusSnapshot()
	if recorder.Code != http.StatusOK || status.PolicyStatus != "published" || !tldEntriesEqual(status.PublishedTLDs, []string{"COM", "NET"}) {
		t.Fatalf("matching AXFR set should recover safely: code=%d status=%+v body=%s", recorder.Code, status, recorder.Body.String())
	}
}

func TestSyncTLDNowPersistsValidatedState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"test-version"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("# Version 7, Last Updated test\nCOM\nCN\n"))
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "tld-state.json")
	t.Setenv("TLD_STATE_FILE", statePath)
	t.Setenv("TLD_SOURCE_URL", server.URL)
	t.Setenv("TLD_DENY_ENABLED", "true")
	t.Setenv("TLD_DENY_PUBLISH_ENABLED", "false")
	t.Setenv("APP_ENV", "development")
	setTLDStatus(TLDStatus{Status: "pending", Source: server.URL})
	if err := syncTLDNow(context.Background()); err != nil {
		t.Fatalf("syncTLDNow returned error: %v", err)
	}
	status := tldStatusSnapshot()
	if status.Status != "ready" || status.TLDCount != 2 || status.Version != "7" || status.ETag != `"test-version"` {
		t.Fatalf("unexpected TLD status: %+v", status)
	}
	content, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("TLD state was not persisted: %v", err)
	}
	if !strings.Contains(string(content), `"tldCount": 2`) {
		t.Fatalf("persisted state missing count: %s", content)
	}
	var persisted TLDStatus
	if err := json.Unmarshal(content, &persisted); err != nil {
		t.Fatal(err)
	}
	if err := syncTLDNow(context.Background()); err != nil {
		t.Fatalf("unchanged TLD sync returned error: %v", err)
	}
	if tldStatusSnapshot().Status != "ready" {
		t.Fatalf("unchanged sync should preserve ready state: %+v", tldStatusSnapshot())
	}
}

func TestSyncTLDNowKeepsPreviousCountOnInvalidDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("# Version 8, Last Updated test\nCOM\nCOM\n"))
	}))
	defer server.Close()
	t.Setenv("TLD_STATE_FILE", filepath.Join(t.TempDir(), "tld-state.json"))
	t.Setenv("TLD_SOURCE_URL", server.URL)
	t.Setenv("TLD_DENY_ENABLED", "true")
	t.Setenv("TLD_DENY_PUBLISH_ENABLED", "false")
	t.Setenv("APP_ENV", "development")
	setTLDStatus(TLDStatus{Status: "ready", Source: server.URL, TLDCount: 1436, Version: "old", TLDs: []string{"COM", "NET"}})
	if err := syncTLDNow(context.Background()); err == nil {
		t.Fatal("invalid document should fail")
	}
	status := tldStatusSnapshot()
	if status.Status != "error" || status.TLDCount != 1436 || status.Version != "old" || !tldEntriesEqual(status.TLDs, []string{"COM", "NET"}) {
		t.Fatalf("invalid update must preserve previous count and version: %+v", status)
	}
}

func TestTLDStatusMethodAndPayload(t *testing.T) {
	setTLDStatus(TLDStatus{Status: "ready", Source: defaultTLDSourceURL, TLDCount: 1436})
	recorder := httptest.NewRecorder()
	tldStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/dns/tld/status", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"tldCount":1436`) {
		t.Fatalf("unexpected TLD status response: code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	tldStatus(recorder, httptest.NewRequest(http.MethodPost, "/api/dns/tld/status", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected method rejection, got %d", recorder.Code)
	}
}
