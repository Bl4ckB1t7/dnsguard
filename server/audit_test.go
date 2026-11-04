package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditEventsCreateHashChainAndRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	t.Setenv("AUDIT_FILE", path)
	t.Setenv("AUDIT_ROTATE_BYTES", "1")
	t.Setenv("AUDIT_ROTATE_BACKUPS", "2")
	original := auditEntries
	auditEntries = nil
	defer func() { auditEntries = original }()

	request := httptest.NewRequest("GET", "/api/audit", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	auditEvent(request, "admin", "rule.create", "success")
	auditEvent(request, "admin", "rule.delete", "success")

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entries []AuditEntry
	if err := json.Unmarshal(content, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Hash == "" {
		t.Fatalf("expected rotated file to contain one hashed entry, got %+v", entries)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected rotated audit backup: %v", err)
	}
	if entries[0].PrevHash == "" {
		t.Fatal("expected hash chain to continue across rotation")
	}
}

func TestAuditSearchAndPagination(t *testing.T) {
	original := auditEntries
	auditEntries = []AuditEntry{
		{Actor: "alice", Action: "rule.create", Result: "success"},
		{Actor: "bob", Action: "publish", Result: "success"},
		{Actor: "alice", Action: "rule.delete", Result: "success"},
	}
	defer func() { auditEntries = original }()

	request := httptest.NewRequest("GET", "/api/audit?q=alice&page=1&pageSize=1", nil)
	recorder := httptest.NewRecorder()
	audit(recorder, request)
	if recorder.Code != 200 {
		t.Fatalf("unexpected response status: %d", recorder.Code)
	}
	var response struct {
		Items []AuditEntry `json:"items"`
		Total int          `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Total != 2 || len(response.Items) != 1 || response.Items[0].Actor != "alice" || response.Items[0].Action != "rule.delete" {
		t.Fatalf("unexpected search result: %+v", response)
	}
}

func TestLoadAuditRejectsTamperedHashChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	t.Setenv("AUDIT_FILE", path)
	entries := []AuditEntry{{Timestamp: "2026-01-01T00:00:00Z", Actor: "admin", Action: "rule.create", Result: "success", Hash: "tampered"}}
	content, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o640); err != nil {
		t.Fatal(err)
	}
	original := auditEntries
	defer func() { auditEntries = original }()
	auditEntries = nil
	defer setAuditIntegrityFailure(nil)
	loadAudit()
	if len(auditEntries) != 0 {
		t.Fatalf("tampered audit entries must not be loaded: %+v", auditEntries)
	}
}

func TestCorruptAuditFailsClosedAndPreservesEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	t.Setenv("AUDIT_FILE", path)
	original := auditEntries
	auditEntries = nil
	defer func() {
		auditEntries = original
		setAuditIntegrityFailure(nil)
	}()
	originalContent := []byte(`[{"Timestamp":"tampered"}]`)
	if err := os.WriteFile(path, originalContent, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := loadAudit(); err == nil {
		t.Fatal("corrupt audit file must enter an error state")
	}
	request := httptest.NewRequest("GET", "/", nil)
	if err := auditEvent(request, "admin", "test", "should-not-write"); err == nil {
		t.Fatal("audit writes must fail closed after integrity failure")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(originalContent) {
		t.Fatalf("corrupt evidence was overwritten: %s", content)
	}
}

func TestAuditRotationBoundaryMustMatchPreviousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.json")
	first := AuditEntry{Timestamp: "2026-01-01T00:00:00Z", Actor: "admin", Action: "one", Result: "success"}
	first.Hash = auditHash(first)
	second := AuditEntry{Timestamp: "2026-01-01T00:00:01Z", Actor: "admin", Action: "two", Result: "success", PrevHash: first.Hash}
	second.Hash = auditHash(second)
	previous, _ := json.Marshal([]AuditEntry{first})
	current, _ := json.Marshal([]AuditEntry{second})
	if err := os.WriteFile(path+".1", previous, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, current, 0o640); err != nil {
		t.Fatal(err)
	}
	var entries []AuditEntry
	if err := json.Unmarshal(current, &entries); err != nil || !validAuditRotationBoundary(path, entries) {
		t.Fatal("valid rotation boundary was rejected")
	}
	second.PrevHash = "wrong"
	second.Hash = auditHash(second)
	current, _ = json.Marshal([]AuditEntry{second})
	if err := os.WriteFile(path, current, 0o640); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(current, &entries) != nil || validAuditRotationBoundary(path, entries) {
		t.Fatal("invalid rotation boundary was accepted")
	}
}
