package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSendTelegramAlert(t *testing.T) {
	var received telegramSendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bottest-token/sendMessage" {
			t.Fatalf("unexpected telegram path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	t.Setenv("TELEGRAM_BOT_TOKEN", "test-token")
	t.Setenv("TELEGRAM_CHAT_ID", "-100123")
	t.Setenv("TELEGRAM_API_URL", server.URL)
	t.Setenv("TELEGRAM_ALERT_EVENTS", "publish_failed")
	t.Setenv("TELEGRAM_ALERT_COOLDOWN_SECONDS", "0")
	telegramAlertMu.Lock()
	telegramLastAlerts = map[string]time.Time{}
	telegramAlertMu.Unlock()

	if err := sendTelegramAlert("publish_failed", "测试告警"); err != nil {
		t.Fatalf("sendTelegramAlert returned error: %v", err)
	}
	if received.ChatID != "-100123" || received.Text != "测试告警" || !received.DisableWebPagePreview {
		t.Fatalf("unexpected telegram payload: %+v", received)
	}
}

func TestSendTelegramAlertSkipsUnconfigured(t *testing.T) {
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")
	if err := sendTelegramAlert("publish_failed", strings.Repeat("x", 3)); err != nil {
		t.Fatalf("unconfigured Telegram should be a no-op: %v", err)
	}
}
