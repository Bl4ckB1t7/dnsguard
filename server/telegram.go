package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var telegramAlertMu sync.Mutex
var telegramLastAlerts = map[string]time.Time{}

type telegramSendMessageRequest struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

type telegramSendMessageResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
}

func telegramAlertCooldown() time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(os.Getenv("TELEGRAM_ALERT_COOLDOWN_SECONDS")))
	if err != nil || seconds < 0 || seconds > 86400 {
		seconds = 300
	}
	return time.Duration(seconds) * time.Second
}

func telegramAlertEnabled(event string) bool {
	if strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")) == "" || strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID")) == "" {
		return false
	}
	events := strings.TrimSpace(os.Getenv("TELEGRAM_ALERT_EVENTS"))
	if events == "" {
		events = "publish_failed,node_down,node_degraded,node_recovered"
	}
	for _, configured := range strings.Split(events, ",") {
		if strings.TrimSpace(configured) == event {
			return true
		}
	}
	return false
}

func telegramAPIURL() string {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("TELEGRAM_API_URL")), "/")
	if base == "" {
		base = "https://api.telegram.org"
	}
	return fmt.Sprintf("%s/bot%s/sendMessage", base, strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")))
}

func sendTelegramAlert(event, message string) error {
	if !telegramAlertEnabled(event) {
		return nil
	}
	if strings.TrimSpace(message) == "" {
		return fmt.Errorf("telegram alert message is empty")
	}

	now := time.Now()
	telegramAlertMu.Lock()
	if last, ok := telegramLastAlerts[event]; ok && telegramAlertCooldown() > 0 && now.Sub(last) < telegramAlertCooldown() {
		telegramAlertMu.Unlock()
		return nil
	}
	telegramLastAlerts[event] = now
	telegramAlertMu.Unlock()

	payload, err := json.Marshal(telegramSendMessageRequest{
		ChatID:                strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID")),
		Text:                  message,
		DisableWebPagePreview: true,
	})
	if err != nil {
		return fmt.Errorf("encode telegram alert: %w", err)
	}
	request, err := http.NewRequest(http.MethodPost, telegramAPIURL(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create telegram alert request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send telegram alert: %w", err)
	}
	defer response.Body.Close()
	var result telegramSendMessageResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode telegram alert response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !result.OK {
		return fmt.Errorf("telegram alert rejected: %s", result.Description)
	}
	return nil
}

func queueTelegramAlert(event, message string) {
	if !telegramAlertEnabled(event) {
		return
	}
	go func() {
		if err := sendTelegramAlert(event, message); err != nil {
			// Alert delivery must never block DNS health checks or RPZ publishing.
			log.Printf("telegram alert failed for %s: %v", event, err)
		}
	}()
}
