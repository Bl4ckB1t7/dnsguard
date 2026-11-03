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
