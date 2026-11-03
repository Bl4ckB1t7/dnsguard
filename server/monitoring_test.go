package main

import (
	"net/http/httptest"
	"testing"
)

func TestMonitoringStatusRequiresToken(t *testing.T) {
	t.Setenv("MONITORING_TOKEN", "monitor-secret")
	request := httptest.NewRequest("GET", "/api/monitoring/status", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	monitoringStatus(recorder, request)
	if recorder.Code != 401 {
		t.Fatalf("expected unauthorized status, got %d", recorder.Code)
	}

	request.Header.Set("Authorization", "Bearer monitor-secret")
	recorder = httptest.NewRecorder()
	monitoringStatus(recorder, request)
	if recorder.Code != 200 {
		t.Fatalf("expected authorized status, got %d", recorder.Code)
	}
}

func TestMonitoringStatusWithoutTokenIsLoopbackOnly(t *testing.T) {
	t.Setenv("MONITORING_TOKEN", "")
	request := httptest.NewRequest("GET", "/api/monitoring/status", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	recorder := httptest.NewRecorder()
	monitoringStatus(recorder, request)
	if recorder.Code != 401 {
		t.Fatalf("expected remote request to be unauthorized, got %d", recorder.Code)
	}

	request.RemoteAddr = "127.0.0.1:1234"
	recorder = httptest.NewRecorder()
	monitoringStatus(recorder, request)
	if recorder.Code != 200 {
		t.Fatalf("expected loopback request to succeed, got %d", recorder.Code)
	}
}
