package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthMeReportsRequiredPasswordChange(t *testing.T) {
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_SECRET", "auth-test-secret-2026-with-enough-length")
	originalAuth := storedAuth
	originalSessions := activeSessions
	defer func() {
		storedAuth = originalAuth
		activeSessions = originalSessions
	}()
	storedAuth = authStore{Username: "admin", PasswordHash: "$2a$10$test", MustChangePassword: true}
	activeSessions = map[string]string{"admin": "session-1"}
	request := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: signSession("admin", 4102444800, "session-1")})
	recorder := httptest.NewRecorder()
	authMe(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["mustChangePassword"] != true {
		t.Fatalf("expected mustChangePassword=true, got %+v", response)
	}
}

func TestPasswordChangeRequiredMiddlewareBlocksDashboard(t *testing.T) {
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_SECRET", "auth-test-secret-2026-with-enough-length")
	originalAuth := storedAuth
	originalSessions := activeSessions
	defer func() {
		storedAuth = originalAuth
		activeSessions = originalSessions
	}()
	storedAuth = authStore{Username: "admin", PasswordHash: "$2a$10$test", MustChangePassword: true}
	activeSessions = map[string]string{"admin": "session-2"}
	request := httptest.NewRequest(http.MethodGet, "/api/dns/overview", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: signSession("admin", 4102444800, "session-2")})
	recorder := httptest.NewRecorder()
	authMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("dashboard should be blocked") })).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPreconditionRequired {
		t.Fatalf("expected 428, got %d", recorder.Code)
	}
}

func TestRequestIPOnlyTrustsForwardedHeadersFromConfiguredProxy(t *testing.T) {
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
	trusted := httptest.NewRequest("GET", "/", nil)
	trusted.RemoteAddr = "127.0.0.1:8080"
	trusted.Header.Set("X-Forwarded-For", "198.51.100.10")
	if got := requestIP(trusted); got != "198.51.100.10" {
		t.Fatalf("trusted proxy IP = %q", got)
	}
	untrusted := httptest.NewRequest("GET", "/", nil)
	untrusted.RemoteAddr = "198.51.100.20:8080"
	untrusted.Header.Set("X-Forwarded-For", "198.51.100.10")
	if got := requestIP(untrusted); got != "198.51.100.20" {
		t.Fatalf("untrusted proxy must not control client IP, got %q", got)
	}
}

func TestAuditEventReturnsWriteFailure(t *testing.T) {
	t.Setenv("AUDIT_FILE", "/dev/null/dnsguard-audit.json")
	defer setAuditIntegrityFailure(nil)
	request := httptest.NewRequest("GET", "/", nil)
	if err := auditEvent(request, "admin", "test", "failure"); err == nil {
		t.Fatal("audit write failure must be returned to the caller")
	}
}

func TestAuditIntegrityFailureBlocksManagementWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	t.Setenv("AUDIT_FILE", path)
	if err := os.WriteFile(path, []byte(`[{"Timestamp":"tampered"}]`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := loadAudit(); err == nil {
		t.Fatal("expected audit integrity failure")
	}
	defer setAuditIntegrityFailure(nil)
	t.Setenv("AUTH_ENABLED", "false")
	request := httptest.NewRequest(http.MethodPost, "/api/dns/rpz", nil)
	recorder := httptest.NewRecorder()
	authMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("management write must be blocked while audit is unhealthy")
	})).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", recorder.Code, recorder.Body.String())
	}
}
