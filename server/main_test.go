package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProductionSecurityRejectsPlaceholderSecret(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_SECRET", "replace-with-a-random-secret-at-least-32-characters")
	t.Setenv("AUTH_FILE", filepath.Join(t.TempDir(), "auth.json"))
	if err := validateSecurityConfig(); err == nil {
		t.Fatal("expected placeholder AUTH_SECRET to be rejected")
	}
}

func TestProductionSecurityRequiresBcryptAuthFile(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_SECRET", "a-long-random-secret-for-production-tests-2026")
	t.Setenv("AUTH_FILE", filepath.Join(t.TempDir(), "auth.json"))
	if err := validateSecurityConfig(); err == nil {
		t.Fatal("expected missing AUTH_FILE to be rejected")
	}
	if _, err := os.Stat(os.Getenv("AUTH_FILE")); !os.IsNotExist(err) {
		t.Fatalf("test auth file unexpectedly exists: %v", err)
	}
}

func TestProductionSecurityRequiresMonitoringToken(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_SECRET", "a-long-random-secret-for-production-tests-2026")
	t.Setenv("MONITORING_TOKEN", "")
	if err := validateSecurityConfig(); err == nil {
		t.Fatal("expected missing MONITORING_TOKEN to be rejected")
	}
}
