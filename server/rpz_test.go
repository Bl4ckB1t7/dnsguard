package main

import "testing"

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
