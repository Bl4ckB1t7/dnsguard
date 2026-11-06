package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHTTPServerHasConnectionTimeouts(t *testing.T) {
	server := newHTTPServer("127.0.0.1:0", http.NewServeMux())
	if server.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("unexpected ReadHeaderTimeout: %s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 15*time.Second {
		t.Fatalf("unexpected ReadTimeout: %s", server.ReadTimeout)
	}
	if server.WriteTimeout != 30*time.Second {
		t.Fatalf("unexpected WriteTimeout: %s", server.WriteTimeout)
	}
	if server.IdleTimeout != 60*time.Second {
		t.Fatalf("unexpected IdleTimeout: %s", server.IdleTimeout)
	}
	if server.MaxHeaderBytes != 1<<20 {
		t.Fatalf("unexpected MaxHeaderBytes: %d", server.MaxHeaderBytes)
	}
}

func TestAuthSecretHasNoBuiltInFallback(t *testing.T) {
	t.Setenv("AUTH_SECRET", "")
	if secret := authSecret(); len(secret) != 0 {
		t.Fatalf("authSecret must not contain a built-in fallback: %q", secret)
	}
}

func TestDevelopmentSecurityRejectsMissingAuthSecret(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_SECRET", "")
	if err := validateSecurityConfig(); err == nil {
		t.Fatal("expected missing AUTH_SECRET to be rejected when authentication is enabled")
	}
}

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

func TestPlatformFirstDeferredStartupRemainsAvailableUntilGlobalDeny(t *testing.T) {
	setupTestEnvironment(t)
	writeInitializedPolicyState(t, "global", true)
	t.Setenv("APP_ENV", "production")
	t.Setenv("MONITORING_TOKEN", "a-long-monitoring-token-for-platform-first-tests-2026")
	t.Setenv("TRUST_PROXY_TLS", "true")
	t.Setenv("DNSGUARD_PLATFORM_ONLY", "true")
	t.Setenv("RPZ_DEFAULT_DENY_MODE", "global")
	t.Setenv("RPZ_GLOBAL_DENY_SETUP_DEFERRED", "true")
	// Platform-first installs do not need a deny zone or recursive baseline
	// until the administrator finishes the BIND-side cutover.
	initialization = initializationState{
		Status:        initializationCompleted,
		PolicyMode:    "global",
		PlatformReady: true,
		BindReady:     false,
	}
	if err := validateSecurityConfig(); err != nil {
		t.Fatalf("platform-only API must restart before BIND attach: %v", err)
	}

	// BIND attachment changes only the persisted readiness marker. The API must
	// remain restartable while the whitelist is still draft or being verified.
	initialization.BindReady = true
	if err := validateSecurityConfig(); err != nil {
		t.Fatalf("API must restart after BIND attach while deferred: %v", err)
	}
	if err := validateSecurityConfig(); err != nil {
		t.Fatalf("API must restart after whitelist publication before Global Deny: %v", err)
	}

	// Finalization removes the temporary switch and restores the normal global
	// configuration requirements. A completed deployment must not retain the
	// deferred startup exception.
	t.Setenv("RPZ_GLOBAL_DENY_SETUP_DEFERRED", "false")
	t.Setenv("RPZ_GLOBAL_DENY_ZONE", "global-deny.rpz.local")
	t.Setenv("RPZ_GLOBAL_DENY_RECURSOR", "10.0.0.53:53")
	t.Setenv("RPZ_GLOBAL_DENY_CHECK_NAME", "baseline.example.com")
	if err := validateSecurityConfig(); err != nil {
		t.Fatalf("API must restart after Global Deny finalization: %v", err)
	}
	initialization.DeploymentCompleted = true
	t.Setenv("RPZ_GLOBAL_DENY_SETUP_DEFERRED", "true")
	if err := validateSecurityConfig(); err == nil {
		t.Fatal("completed platform-first deployment must reject a stale deferred switch")
	}
}

func TestFreshPlatformFirstStartupAllowsMissingGlobalDenyInputs(t *testing.T) {
	setupTestEnvironment(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("MONITORING_TOKEN", "a-long-monitoring-token-for-fresh-platform-first-tests-2026")
	t.Setenv("TRUST_PROXY_TLS", "true")
	t.Setenv("DNSGUARD_PLATFORM_ONLY", "true")
	t.Setenv("RPZ_DEFAULT_DENY_MODE", "global")
	t.Setenv("RPZ_GLOBAL_DENY_SETUP_DEFERRED", "true")
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_SECRET", "setup-test-secret-with-more-than-32-characters-2026")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	t.Setenv("RPZ_GLOBAL_DENY_ZONE", "global-deny.rpz.local")
	t.Setenv("RPZ_GLOBAL_DENY_RECURSOR", "")
	t.Setenv("RPZ_GLOBAL_DENY_CHECK_NAME", "")

	if isInitialized() {
		t.Fatal("fresh platform-first test must not start initialized")
	}
	if err := validateSecurityConfig(); err != nil {
		t.Fatalf("fresh platform-first API must start before Global Deny inputs exist: %v", err)
	}
}

func TestLegacyDeferredStartupGuardRemains(t *testing.T) {
	setupTestEnvironment(t)
	writeInitializedPolicyState(t, "global", true)
	t.Setenv("APP_ENV", "production")
	t.Setenv("MONITORING_TOKEN", "a-long-monitoring-token-for-legacy-tests-2026")
	t.Setenv("TRUST_PROXY_TLS", "true")
	t.Setenv("DNSGUARD_PLATFORM_ONLY", "false")
	t.Setenv("RPZ_DEFAULT_DENY_MODE", "global")
	t.Setenv("RPZ_GLOBAL_DENY_SETUP_DEFERRED", "true")
	t.Setenv("RPZ_GLOBAL_DENY_ZONE", "global-deny.rpz.local")
	t.Setenv("RPZ_GLOBAL_DENY_RECURSOR", "10.0.0.53:53")
	t.Setenv("RPZ_GLOBAL_DENY_CHECK_NAME", "baseline.example.com")
	initialization = initializationState{
		Status:        initializationCompleted,
		Primary:       "127.0.0.1:5353",
		PolicyMode:    "global",
		BindReady:     false,
		PlatformReady: false,
	}
	if err := validateSecurityConfig(); err == nil {
		t.Fatal("legacy completed deployment must keep rejecting stale deferred startup")
	}
}
