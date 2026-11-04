package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPublishJobExecutionSlot(t *testing.T) {
	activePublishID = ""
	if !reservePublishJob("job-1") {
		t.Fatal("first publish job should reserve the execution slot")
	}
	if reservePublishJob("job-2") {
		t.Fatal("second publish job must be rejected while one is active")
	}
	if got := activePublishJob(); got != "job-1" {
		t.Fatalf("active job = %q, want job-1", got)
	}
	releasePublishJob("job-2")
	if got := activePublishJob(); got != "job-1" {
		t.Fatalf("wrong job released the active slot: %q", got)
	}
	releasePublishJob("job-1")
	if active := activePublishJob(); active != "" {
		t.Fatalf("publish slot remains occupied by %q", active)
	}
}

func TestRollbackReservationHandoffIsAtomic(t *testing.T) {
	original := activePublishID
	defer func() { activePublishID = original }()
	activePublishID = ""
	if !reservePublishJob("rollback-1") {
		t.Fatal("rollback should reserve the execution slot")
	}
	if reservePublishJob("publish-1") {
		t.Fatal("publish must not enter while rollback owns the slot")
	}
	if !handoffPublishJob("rollback-1", "publish-1") {
		t.Fatal("rollback reservation handoff failed")
	}
	releasePublishJob("rollback-1")
	if activePublishJob() != "publish-1" {
		t.Fatalf("old reservation release cleared the handed-off job: %q", activePublishJob())
	}
	releasePublishJob("publish-1")
}

func TestConcurrentReservationsAllowOnlyOneOwner(t *testing.T) {
	original := activePublishID
	defer func() { activePublishID = original }()
	activePublishID = ""
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < 32; i++ {
		id := fmt.Sprintf("job-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if reservePublishJob(id) {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("reservation winners=%d, want 1", winners)
	}
	releasePublishJob(activePublishJob())
}

func TestPublishRejectsWhenThereAreNoPendingChanges(t *testing.T) {
	original := state
	defer func() { state = original }()
	state = dnsState{Rules: []RPZRule{{ID: "rule-1", Domain: "example.com", Action: "passthru", Type: "CNAME"}}, Published: []RPZRule{{ID: "published-1", Domain: "example.com", Action: "passthru", Type: "CNAME"}}}
	request := httptest.NewRequest(http.MethodPost, "/api/dns/rpz/publish", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	publishRPZ(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected duplicate/no-op publish to be rejected, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPublishRejectsWhileReconciliationIsRequired(t *testing.T) {
	originalState := state
	originalJobs := publishJobs
	originalActive := activePublishID
	defer func() {
		state = originalState
		publishJobs = originalJobs
		activePublishID = originalActive
	}()
	state = dnsState{Rules: []RPZRule{{Domain: "pending.example.com", Action: "passthru", Type: "CNAME"}}}
	publishJobs = map[string]PublishJob{"job-reconcile": {ID: "job-reconcile", Status: "reconcile_required"}}
	activePublishID = ""
	request := httptest.NewRequest(http.MethodPost, "/api/dns/rpz/publish", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	publishRPZ(recorder, request)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "job-reconcile") {
		t.Fatalf("reconciliation gate should reject publish, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestLoadPublishJobsRecoversInFlightTask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publish-jobs.json")
	t.Setenv("RPZ_PUBLISH_JOBS_FILE", path)
	content, err := json.Marshal([]PublishJob{{ID: "job-1", Status: "running", CreatedAt: "2026-01-01T00:00:00Z"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o640); err != nil {
		t.Fatal(err)
	}
	originalJobs := publishJobs
	originalRuntime := rpzRuntimeState
	defer func() {
		publishJobs = originalJobs
		rpzRuntimeState = originalRuntime
	}()
	publishJobs = map[string]PublishJob{}
	if err := loadPublishJobs(); err != nil {
		t.Fatal(err)
	}
	job, ok := getPublishJob("job-1")
	if !ok || job.Status != "reconcile_required" || job.Error == "" {
		t.Fatalf("in-flight task was not recovered safely: ok=%v job=%+v", ok, job)
	}
}

func TestLoadPublishJobsRejectsCorruptStateWithoutOverwritingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publish-jobs.json")
	t.Setenv("RPZ_PUBLISH_JOBS_FILE", path)
	content := []byte("{not-json")
	if err := os.WriteFile(path, content, 0o640); err != nil {
		t.Fatal(err)
	}
	originalJobs := publishJobs
	publishJobs = map[string]PublishJob{"existing": {ID: "existing", Status: "succeeded"}}
	defer func() { publishJobs = originalJobs }()
	if err := loadPublishJobs(); err == nil {
		t.Fatal("corrupt publish job state must fail closed")
	}
	if got := publishJobs["existing"].Status; got != "succeeded" {
		t.Fatalf("corrupt load replaced in-memory jobs: %+v", publishJobs)
	}
	readBack, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(readBack) != string(content) {
		t.Fatalf("corrupt publish job evidence was overwritten: %s", readBack)
	}
}

func TestNSUpdateRetriesUntilSuccess(t *testing.T) {
	t.Setenv("RPZ_PUBLISH_RETRIES", "2")
	t.Setenv("RPZ_PUBLISH_RETRY_BACKOFF_SECONDS", "0")
	original := runNSUpdateFunc
	defer func() { runNSUpdateFunc = original }()
	attempts := 0
	runNSUpdateFunc = func(context.Context, []RPZRule, []RPZRule) error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary failure")
		}
		return nil
	}
	used, err := runNSUpdateWithRetry(context.Background(), nil, nil)
	if err != nil || used != 3 || attempts != 3 {
		t.Fatalf("expected three attempts and success, used=%d attempts=%d err=%v", used, attempts, err)
	}
}

func TestNSUpdateRetryHonorsRetryLimit(t *testing.T) {
	t.Setenv("RPZ_PUBLISH_RETRIES", "1")
	t.Setenv("RPZ_PUBLISH_RETRY_BACKOFF_SECONDS", "0")
	original := runNSUpdateFunc
	defer func() { runNSUpdateFunc = original }()
	attempts := 0
	runNSUpdateFunc = func(context.Context, []RPZRule, []RPZRule) error {
		attempts++
		return errors.New("persistent failure")
	}
	used, err := runNSUpdateWithRetry(context.Background(), nil, nil)
	if err == nil || used != 2 || attempts != 2 {
		t.Fatalf("expected retry limit failure, used=%d attempts=%d err=%v", used, attempts, err)
	}
}

func TestUpdatePublishJobFailsClosedWhenStateCannotBePersisted(t *testing.T) {
	t.Setenv("RPZ_PUBLISH_JOBS_FILE", "/dev/null/publish-jobs.json")
	originalJobs := publishJobs
	defer func() { publishJobs = originalJobs }()
	publishJobs = map[string]PublishJob{"job-1": {ID: "job-1", Status: "queued"}}
	job, err := updatePublishJob("job-1", func(job *PublishJob) { job.Status = "running" })
	if err == nil {
		t.Fatal("state persistence failure must be returned")
	}
	if job.Status != "reconcile_required" || job.SyncStatus != "reconcile_required" {
		t.Fatalf("job must enter reconcile_required, got %+v", job)
	}
	if got := publishJobs["job-1"].Status; got != "reconcile_required" {
		t.Fatalf("in-memory job status = %q", got)
	}
}

func TestRunPublishJobDoesNotPublishWhenRunningStateCannotBePersisted(t *testing.T) {
	t.Setenv("RPZ_PUBLISH_JOBS_FILE", "/dev/null/publish-jobs.json")
	originalJobs := publishJobs
	originalActive := activePublishID
	originalPerform := performPublishFunc
	defer func() {
		publishJobs = originalJobs
		activePublishID = originalActive
		performPublishFunc = originalPerform
	}()
	publishJobs = map[string]PublishJob{"job-1": {ID: "job-1", Status: "queued"}}
	activePublishID = "job-1"
	called := false
	performPublishFunc = func(context.Context, string, string) (publishResult, error) {
		called = true
		return publishResult{Status: "published"}, nil
	}
	runPublishJob("job-1", "admin", "127.0.0.1:1")
	if called {
		t.Fatal("nsupdate workflow must not start after running-state persistence failure")
	}
	if job := publishJobs["job-1"]; job.Status != "reconcile_required" {
		t.Fatalf("job status = %q, want reconcile_required", job.Status)
	}
	if activePublishJob() != "" {
		t.Fatal("publish execution slot was not released")
	}
}

func TestFinishPublishKeepsRulesChangedDuringPublishAsDraft(t *testing.T) {
	t.Setenv("DNS_STATE_FILE", filepath.Join(t.TempDir(), "dns-state.json"))
	t.Setenv("AUDIT_FILE", filepath.Join(t.TempDir(), "audit.json"))
	setAuditIntegrityFailure(nil)
	originalState := state
	originalRuntime := rpzRuntimeState
	defer func() {
		state = originalState
		rpzRuntimeState = originalRuntime
	}()
	snapshot := RPZRule{ID: "rule-1", Domain: "snapshot.example.com", Action: "passthru", Type: "CNAME", Status: "draft"}
	draft := RPZRule{ID: "rule-2", Domain: "new.example.com", Action: "passthru", Type: "CNAME", Status: "draft"}
	state = dnsState{Rules: []RPZRule{snapshot, draft}, Published: []RPZRule{}, RulesRevision: 2}
	if _, err := finishPublish("admin", "127.0.0.1:1", []RPZRule{snapshot}, nil, 1, "ok", "nsupdate", "published", 1, "published snapshot", nil); err != nil {
		t.Fatal(err)
	}
	if len(state.Published) != 1 || state.Published[0].Domain != snapshot.Domain {
		t.Fatalf("published snapshot was polluted: %+v", state.Published)
	}
	if state.Rules[0].Status != "published" || state.Rules[1].Status != "draft" {
		t.Fatalf("rule statuses crossed snapshot boundary: %+v", state.Rules)
	}
}

func TestFinishPublishStateWriteFailureRequiresReconciliation(t *testing.T) {
	t.Setenv("DNS_STATE_FILE", "/dev/null/dns-state.json")
	t.Setenv("AUDIT_FILE", filepath.Join(t.TempDir(), "audit.json"))
	setAuditIntegrityFailure(nil)
	originalState := state
	defer func() { state = originalState }()
	rule := RPZRule{ID: "rule-1", Domain: "state-failure.example.com", Action: "passthru", Type: "CNAME", Status: "draft"}
	state = dnsState{Rules: []RPZRule{rule}, RulesRevision: 1}
	result, err := finishPublish("admin", "127.0.0.1:1", []RPZRule{rule}, nil, 1, "ok", "nsupdate", "published", 1, "published", nil)
	if err == nil || result.Status != "reconcile_required" || result.SyncStatus != "reconcile_required" {
		t.Fatalf("state write failure must require reconciliation, result=%+v err=%v", result, err)
	}
}

func TestRollbackStateWriteFailureReleasesReservation(t *testing.T) {
	t.Setenv("DNS_STATE_FILE", "/dev/null/dns-state.json")
	originalState := state
	originalActive := activePublishID
	defer func() {
		state = originalState
		activePublishID = originalActive
	}()
	state = dnsState{
		Rules:         []RPZRule{{ID: "current", Domain: "current.example.com", Action: "passthru", Type: "CNAME"}},
		Versions:      []RPZVersion{{ID: "version-1", Rules: []RPZRule{{ID: "old", Domain: "old.example.com", Action: "passthru", Type: "CNAME"}}}},
		RulesRevision: 3,
	}
	activePublishID = ""
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/dns/rpz/rollback", strings.NewReader(`{"versionId":"version-1"}`))
	rollbackRPZ(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("rollback save failure status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if activePublishJob() != "" {
		t.Fatal("rollback reservation remained after state write failure")
	}
	if state.Rules[0].Domain != "current.example.com" {
		t.Fatalf("rollback state was not restored: %+v", state.Rules)
	}
}
