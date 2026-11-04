package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
