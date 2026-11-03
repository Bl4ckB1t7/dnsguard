package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
