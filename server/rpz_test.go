package main

import (
	"context"
	"errors"
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
