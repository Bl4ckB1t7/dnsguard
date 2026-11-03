package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	telegramAlertsInFlight = map[string]bool{}
	telegramAlertMu.Unlock()

	if err := sendTelegramAlert("publish_failed", "测试告警"); err != nil {
		t.Fatalf("sendTelegramAlert returned error: %v", err)
	}
	if received.ChatID != "-100123" || received.Text != "测试告警" || !received.DisableWebPagePreview {
		t.Fatalf("unexpected telegram payload: %+v", received)
	}
}

func TestRPZRuleAlertsAreNotSuppressedByCooldown(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	t.Setenv("TELEGRAM_BOT_TOKEN", "test-token")
	t.Setenv("TELEGRAM_CHAT_ID", "-100123")
	t.Setenv("TELEGRAM_API_URL", server.URL)
	telegramConfigMu.Lock()
	original := telegramConfig
	telegramConfig = TelegramConfig{BotToken: "test-token", ChatID: "-100123", Events: []string{"rpz_rule_create"}, CooldownSeconds: 300}
	telegramConfigMu.Unlock()
	defer func() {
		telegramConfigMu.Lock()
		telegramConfig = original
		telegramConfigMu.Unlock()
	}()
	telegramAlertMu.Lock()
	telegramLastAlerts = map[string]time.Time{}
	telegramAlertsInFlight = map[string]bool{}
	telegramAlertMu.Unlock()

	if err := sendTelegramAlert("rpz_rule_create", "规则一"); err != nil {
		t.Fatalf("first RPZ alert returned error: %v", err)
	}
	if err := sendTelegramAlert("rpz_rule_create", "规则二"); err != nil {
		t.Fatalf("second RPZ alert returned error: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected both RPZ operations to be delivered, got %d requests", got)
	}
}

func TestFailedTelegramDeliveryDoesNotConsumeCooldown(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"ok":false,"description":"temporary failure"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	t.Setenv("TELEGRAM_BOT_TOKEN", "test-token")
	t.Setenv("TELEGRAM_CHAT_ID", "-100123")
	t.Setenv("TELEGRAM_API_URL", server.URL)
	config := TelegramConfig{BotToken: "test-token", ChatID: "-100123", CooldownSeconds: 300}
	telegramAlertMu.Lock()
	telegramLastAlerts = map[string]time.Time{}
	telegramAlertsInFlight = map[string]bool{}
	telegramAlertMu.Unlock()

	if err := sendTelegramMessage(config, "第一次发送", true, "publish_failed"); err == nil {
		t.Fatal("expected the first Telegram delivery to fail")
	}
	if err := sendTelegramMessage(config, "第二次发送", true, "publish_failed"); err != nil {
		t.Fatalf("second Telegram delivery should retry after failure: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected a retry after failed delivery, got %d requests", got)
	}
}

func TestSendTelegramAlertSkipsUnconfigured(t *testing.T) {
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")
	if err := sendTelegramAlert("publish_failed", strings.Repeat("x", 3)); err != nil {
		t.Fatalf("unconfigured Telegram should be a no-op: %v", err)
	}
}

func TestTelegramSettingsCanBeSavedFromAPI(t *testing.T) {
	t.Setenv("TELEGRAM_CONFIG_FILE", filepath.Join(t.TempDir(), "telegram.json"))
	t.Setenv("AUDIT_FILE", filepath.Join(t.TempDir(), "audit.json"))
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")
	telegramConfigMu.Lock()
	original := telegramConfig
	telegramConfig = defaultTelegramConfig()
	telegramConfigMu.Unlock()
	defer func() {
		telegramConfigMu.Lock()
		telegramConfig = original
		telegramConfigMu.Unlock()
	}()

	request := httptest.NewRequest(http.MethodPut, "/api/settings/telegram", strings.NewReader(`{"botToken":"secret-token","chatId":"-100123","events":["publish_failed"],"cooldownSeconds":60}`))
	recorder := httptest.NewRecorder()
	telegramSettings(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected settings save to succeed, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "secret-token") {
		t.Fatal("Telegram API response must not expose the bot token")
	}
	var response telegramSettingsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Enabled || !response.BotTokenSet || response.ChatID != "-100123" {
		t.Fatalf("unexpected Telegram settings response: %+v", response)
	}
	info, err := os.Stat(telegramConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("Telegram config should be owner-readable only, mode=%o", info.Mode().Perm())
	}
}
