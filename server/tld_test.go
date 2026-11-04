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
)

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
	t.Setenv("APP_ENV", "development")
	setTLDStatus(TLDStatus{Status: "ready", Source: server.URL, TLDCount: 1436, Version: "old"})
	if err := syncTLDNow(context.Background()); err == nil {
		t.Fatal("invalid document should fail")
	}
	status := tldStatusSnapshot()
	if status.Status != "error" || status.TLDCount != 1436 || status.Version != "old" {
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
