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

func TestProductionRuntimePreflightRejectsMissingNodeConfig(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_SECRET", "a-long-random-secret-for-production-tests-2026")
	t.Setenv("MONITORING_TOKEN", "a-long-monitoring-token-for-production-tests-2026")
	t.Setenv("AUTH_FILE", filepath.Join(t.TempDir(), "auth.json"))
	if err := os.WriteFile(os.Getenv("AUTH_FILE"), []byte(`{"passwordHash":"$2a$10$valid-test-placeholder"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DNS_NODE_CONFIG_FILE", filepath.Join(t.TempDir(), "missing-nodes.json"))
	t.Setenv("TRUST_PROXY_TLS", "true")
	if err := validateSecurityConfig(); err == nil {
		t.Fatal("expected missing node config to fail production preflight")
	}
}

func TestProductionRuntimePreflightAcceptsConfiguredFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "production")
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_SECRET", "a-long-random-secret-for-production-tests-2026")
	t.Setenv("MONITORING_TOKEN", "a-long-monitoring-token-for-production-tests-2026")
	t.Setenv("AUTH_FILE", filepath.Join(dir, "auth.json"))
	t.Setenv("DNS_NODE_CONFIG_FILE", filepath.Join(dir, "nodes.json"))
	t.Setenv("DNS_STATE_FILE", filepath.Join(dir, "data", "state.json"))
	t.Setenv("AUDIT_FILE", filepath.Join(dir, "data", "audit.json"))
	t.Setenv("RPZ_ARTIFACT_FILE", filepath.Join(dir, "data", "rpz.db"))
	t.Setenv("TRUST_PROXY_TLS", "true")
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]struct {
		content string
		mode    os.FileMode
	}{
		os.Getenv("AUTH_FILE"):            {content: `{"passwordHash":"$2a$10$valid-test-placeholder"}`, mode: 0o600},
		os.Getenv("DNS_NODE_CONFIG_FILE"): {content: `[{"id":"primary-1","address":"127.0.0.1:53"}]`, mode: 0o640},
	} {
		if err := os.WriteFile(path, []byte(content.content), content.mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateSecurityConfig(); err != nil {
		t.Fatalf("expected production preflight to pass: %v", err)
	}
}
