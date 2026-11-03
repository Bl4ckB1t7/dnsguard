package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TelegramConfig struct {
	BotToken        string   `json:"botToken"`
	ChatID          string   `json:"chatId"`
	Events          []string `json:"events"`
	CooldownSeconds int      `json:"cooldownSeconds"`
}

type telegramSettingsResponse struct {
	Enabled         bool     `json:"enabled"`
	BotTokenSet     bool     `json:"botTokenSet"`
	BotTokenHint    string   `json:"botTokenHint,omitempty"`
	ChatID          string   `json:"chatId"`
	Events          []string `json:"events"`
	CooldownSeconds int      `json:"cooldownSeconds"`
}

var telegramAlertMu sync.Mutex
var telegramConfigMu sync.RWMutex
var telegramConfig = defaultTelegramConfig()
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

func defaultTelegramEvents() []string {
	return []string{"publish_failed", "rpz_rule_create", "rpz_rule_update", "rpz_rule_delete", "rpz_publish_success", "rpz_rollback", "node_down", "node_degraded", "node_recovered"}
}

func rpzRuleTelegramMessage(action string, rule RPZRule) string {
	target := rule.Value
	if target == "" {
		target = "PASSTHRU"
	}
	return fmt.Sprintf("🛡️ 域盾 DNSGuard RPZ 操作\n操作：%s\n域名：%s\n类型：%s\n目标：%s\n原因：%s", action, rule.Domain, rule.Type, target, rule.Reason)
}

func defaultTelegramConfig() TelegramConfig {
	return TelegramConfig{Events: defaultTelegramEvents(), CooldownSeconds: 300}
}

func telegramConfigPath() string {
	if path := strings.TrimSpace(os.Getenv("TELEGRAM_CONFIG_FILE")); path != "" {
		return path
	}
	return filepath.Join("data", "telegram.json")
}

func normalizeTelegramConfig(config TelegramConfig) TelegramConfig {
	if config.Events == nil {
		config.Events = defaultTelegramEvents()
	}
	seen := make(map[string]bool, len(config.Events))
	events := make([]string, 0, len(config.Events))
	for _, event := range config.Events {
		event = strings.TrimSpace(event)
		if event != "" && !seen[event] {
			seen[event] = true
			events = append(events, event)
		}
	}
	if len(events) == 0 {
		events = defaultTelegramEvents()
	}
	config.Events = events
	if config.CooldownSeconds < 0 || config.CooldownSeconds > 86400 {
		config.CooldownSeconds = 300
	}
	return config
}

func loadTelegramConfig() error {
	config := defaultTelegramConfig()
	content, err := os.ReadFile(telegramConfigPath())
	if err == nil {
		if err := json.Unmarshal(content, &config); err != nil {
			return fmt.Errorf("解析 Telegram 配置失败: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("读取 Telegram 配置失败: %w", err)
	}
	// Keep a short migration path for existing deployments that used env values.
	if config.BotToken == "" {
		config.BotToken = strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	}
	if config.ChatID == "" {
		config.ChatID = strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
	}
	if len(config.Events) == 0 {
		if value := strings.TrimSpace(os.Getenv("TELEGRAM_ALERT_EVENTS")); value != "" {
			config.Events = strings.Split(value, ",")
		}
	}
	if value := strings.TrimSpace(os.Getenv("TELEGRAM_ALERT_COOLDOWN_SECONDS")); value != "" && config.CooldownSeconds == 300 {
		if seconds, parseErr := strconv.Atoi(value); parseErr == nil {
			config.CooldownSeconds = seconds
		}
	}
	telegramConfigMu.Lock()
	telegramConfig = normalizeTelegramConfig(config)
	telegramConfigMu.Unlock()
	return nil
}

func currentTelegramConfig() TelegramConfig {
	telegramConfigMu.RLock()
	config := telegramConfig
	config.Events = append([]string{}, config.Events...)
	telegramConfigMu.RUnlock()
	// Tests and old installations can still provide values through env until the UI saves a file.
	if config.BotToken == "" {
		config.BotToken = strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	}
	if config.ChatID == "" {
		config.ChatID = strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
	}
	return normalizeTelegramConfig(config)
}

func saveTelegramConfig(config TelegramConfig) error {
	config = normalizeTelegramConfig(config)
	path := telegramConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".telegram-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	telegramConfigMu.Lock()
	telegramConfig = config
	telegramConfigMu.Unlock()
	return nil
}

func telegramSettingsPayload(config TelegramConfig) telegramSettingsResponse {
	token := strings.TrimSpace(config.BotToken)
	hint := ""
	if len(token) > 4 {
		hint = "••••" + token[len(token)-4:]
	}
	return telegramSettingsResponse{Enabled: token != "" && strings.TrimSpace(config.ChatID) != "", BotTokenSet: token != "", BotTokenHint: hint, ChatID: config.ChatID, Events: append([]string{}, config.Events...), CooldownSeconds: config.CooldownSeconds}
}

func telegramSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, telegramSettingsPayload(currentTelegramConfig()))
	case http.MethodPut:
		var request struct {
			BotToken        string   `json:"botToken"`
			ClearToken      bool     `json:"clearToken"`
			ChatID          string   `json:"chatId"`
			Events          []string `json:"events"`
			CooldownSeconds int      `json:"cooldownSeconds"`
		}
		if err := decodeJSON(r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Telegram 配置格式无效"})
			return
		}
		config := currentTelegramConfig()
		if request.ClearToken {
			config.BotToken = ""
		} else if strings.TrimSpace(request.BotToken) != "" {
			config.BotToken = strings.TrimSpace(request.BotToken)
		}
		config.ChatID = strings.TrimSpace(request.ChatID)
		config.Events = request.Events
		config.CooldownSeconds = request.CooldownSeconds
		config = normalizeTelegramConfig(config)
		if config.BotToken != "" && config.ChatID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "已配置 Bot Token 时必须填写 Chat ID"})
			return
		}
		if err := saveTelegramConfig(config); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Telegram 配置保存失败"})
			return
		}
		auditEvent(r, authUsername(), "telegram.settings.update", telegramSettingsAuditResult(config))
		writeJSON(w, http.StatusOK, telegramSettingsPayload(config))
	default:
		w.Header().Set("Allow", "GET, PUT")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func telegramSettingsAuditResult(config TelegramConfig) string {
	if config.BotToken == "" || config.ChatID == "" {
		return "disabled"
	}
	return "enabled chat=" + config.ChatID
}

func telegramTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	config := currentTelegramConfig()
	if config.BotToken == "" || config.ChatID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请先保存 Telegram Bot Token 和 Chat ID"})
		return
	}
	if err := sendTelegramMessage(config, "🔔 域盾 DNSGuard Telegram 告警测试\n配置已生效。", false, "test"); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Telegram 测试消息发送失败"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}

func telegramAlertCooldown(config TelegramConfig) time.Duration {
	return time.Duration(config.CooldownSeconds) * time.Second
}

func telegramAlertEnabled(event string) bool {
	config := currentTelegramConfig()
	if strings.TrimSpace(config.BotToken) == "" || strings.TrimSpace(config.ChatID) == "" {
		return false
	}
	for _, configured := range config.Events {
		if configured == event {
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
	return fmt.Sprintf("%s/bot%s/sendMessage", base, strings.TrimSpace(currentTelegramConfig().BotToken))
}

func sendTelegramMessage(config TelegramConfig, message string, useCooldown bool, cooldownKey string) error {
	if strings.TrimSpace(message) == "" {
		return fmt.Errorf("telegram alert message is empty")
	}
	if useCooldown {
		now := time.Now()
		telegramAlertMu.Lock()
		if last, ok := telegramLastAlerts[cooldownKey]; ok && telegramAlertCooldown(config) > 0 && now.Sub(last) < telegramAlertCooldown(config) {
			telegramAlertMu.Unlock()
			return nil
		}
		telegramLastAlerts[cooldownKey] = now
		telegramAlertMu.Unlock()
	}
	payload, err := json.Marshal(telegramSendMessageRequest{ChatID: strings.TrimSpace(config.ChatID), Text: message, DisableWebPagePreview: true})
	if err != nil {
		return fmt.Errorf("encode telegram alert: %w", err)
	}
	request, err := http.NewRequest(http.MethodPost, telegramAPIURL(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create telegram alert request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return fmt.Errorf("send telegram alert: %w", err)
	}
	defer response.Body.Close()
	var result telegramSendMessageResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result); err != nil {
		return fmt.Errorf("decode telegram alert response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !result.OK {
		return fmt.Errorf("telegram alert rejected: %s", result.Description)
	}
	return nil
}

func sendTelegramAlert(event, message string) error {
	config := currentTelegramConfig()
	if !telegramAlertEnabled(event) {
		return nil
	}
	return sendTelegramMessage(config, message, true, event)
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
