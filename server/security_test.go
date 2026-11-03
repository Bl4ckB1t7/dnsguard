package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeadersAreSet(t *testing.T) {
	t.Setenv("AUTH_ENABLED", "false")
	t.Setenv("TRUST_PROXY_TLS", "false")
	request := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	recorder := httptest.NewRecorder()
	authMiddleware(http.HandlerFunc(health)).ServeHTTP(recorder, request)
	for key, expected := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
	} {
		if got := recorder.Header().Get(key); got != expected {
			t.Fatalf("%s = %q, want %q", key, got, expected)
		}
	}
	if got := recorder.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("unexpected HSTS on plain HTTP: %q", got)
	}
}

func TestSecurityHeadersTrustConfiguredHTTPSProxy(t *testing.T) {
	t.Setenv("AUTH_ENABLED", "false")
	t.Setenv("TRUST_PROXY_TLS", "true")
	request := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	recorder := httptest.NewRecorder()
	authMiddleware(http.HandlerFunc(health)).ServeHTTP(recorder, request)
	if got := recorder.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
		t.Fatalf("HSTS = %q", got)
	}
}
