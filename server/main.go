package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSON(r *http.Request, target any) error {
	return json.NewDecoder(r.Body).Decode(target)
}

type Health struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Time    string `json:"time"`
}

func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, Health{Status: "ok", Service: "dnsguard-api", Time: time.Now().UTC().Format(time.RFC3339)})
}

func settings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"title":    "域盾 DNSGuard",
		"subtitle": "DNS 安全策略管理平台",
	})
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func main() {
	if err := loadInitializationState(); err != nil {
		log.Fatal(err)
	}
	if err := loadDNSState(); err != nil {
		log.Fatal(err)
	}
	if err := validateSecurityConfig(); err != nil {
		log.Fatal(err)
	}
	if err := loadTLDState(); err != nil {
		log.Printf("TLD 状态不可用，将在后台尝试重新同步: %v", err)
	}
	if err := loadPublishJobs(); err != nil {
		log.Fatal(err)
	}
	if err := loadDNSNodeConfig(); err != nil {
		log.Fatal(err)
	}
	if err := loadAudit(); err != nil {
		log.Printf("audit integrity unavailable; management writes will be blocked: %v", err)
	}
	loadAuth()
	if err := loadTelegramConfig(); err != nil {
		log.Fatal(err)
	}
	startDNSHealthMonitor()
	startTLDSyncMonitor()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", health)
	mux.HandleFunc("/api/monitoring/status", monitoringStatus)
	mux.HandleFunc("/api/settings", settings)
	mux.HandleFunc("/api/setup/status", setupStatus)
	mux.HandleFunc("/api/setup/validate", setupValidate)
	mux.HandleFunc("/api/setup/complete", setupComplete)
	mux.HandleFunc("/api/settings/telegram", telegramSettings)
	mux.HandleFunc("/api/settings/telegram/test", telegramTest)
	mux.HandleFunc("/api/auth/login", authLogin)
	mux.HandleFunc("/api/auth/captcha", captcha)
	mux.HandleFunc("/api/auth/me", authMe)
	mux.HandleFunc("/api/auth/logout", authLogout)
	mux.HandleFunc("/api/auth/password", authPasswordChange)
	mux.HandleFunc("/api/dns/overview", dnsOverview)
	mux.HandleFunc("/api/dns/global-deny/check", globalDenyCheck)
	mux.HandleFunc("/api/dns/tld/status", tldStatus)
	mux.HandleFunc("/api/dns/tld/reconcile", reconcileTLDPolicy)
	mux.HandleFunc("/api/dns/nodes", dnsNodes)
	mux.HandleFunc("/api/dns/nodes/", dnsNodeByID)
	mux.HandleFunc("/api/dns/records", dnsRecords)
	mux.HandleFunc("/api/dns/rpz", dnsRules)
	mux.HandleFunc("/api/dns/rpz/bulk", dnsBulkRules)
	mux.HandleFunc("/api/dns/rpz/preview", rpzPreview)
	mux.HandleFunc("/api/dns/rpz/versions", rpzVersions)
	mux.HandleFunc("/api/dns/rpz/jobs/", publishJobByID)
	mux.HandleFunc("/api/dns/rpz/publish", publishRPZ)
	mux.HandleFunc("/api/dns/rpz/rollback", rollbackRPZ)
	mux.HandleFunc("/api/dns/rpz/", dnsRuleByID)
	mux.HandleFunc("/api/audit", audit)

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8080"
	}
	server := newHTTPServer(listenAddr, authMiddleware(mux))
	log.Printf("DNSGuard API listening on %s", server.Addr)
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile != "" && keyFile != "" {
		log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
	}
	log.Fatal(server.ListenAndServe())
}

func validateSecurityConfig() error {
	if err := configuredPolicyModeError(); err != nil {
		return err
	}
	if authEnabled() && strings.TrimSpace(os.Getenv("AUTH_SECRET")) == "" {
		return fmt.Errorf("AUTH_SECRET must be configured when authentication is enabled")
	}
	if os.Getenv("APP_ENV") != "production" {
		return nil
	}
	secret := os.Getenv("AUTH_SECRET")
	if len(secret) < 32 || secret == "replace-with-a-random-secret-at-least-32-characters" || secret == "change-this-network-visualizer-secret" {
		return fmt.Errorf("AUTH_SECRET must be at least 32 characters in production")
	}
	if !authEnabled() {
		return fmt.Errorf("AUTH_ENABLED must be true in production")
	}
	monitoringToken := os.Getenv("MONITORING_TOKEN")
	if len(monitoringToken) < 32 || monitoringToken == "replace-with-a-random-monitoring-token" {
		return fmt.Errorf("MONITORING_TOKEN must be at least 32 characters in production")
	}
	initialized := isInitialized()
	bindReady := bindReadyStatus()
	if initialized && !authFileHasPasswordHash() {
		return fmt.Errorf("AUTH_FILE must contain a bcrypt password hash")
	}
	if !initialized {
		if err := validateBootstrapTokenFile(); err != nil {
			return err
		}
	}
	if (os.Getenv("TLS_CERT_FILE") == "" || os.Getenv("TLS_KEY_FILE") == "") && os.Getenv("TRUST_PROXY_TLS") != "true" {
		return fmt.Errorf("configure TLS_CERT_FILE/TLS_KEY_FILE or set TRUST_PROXY_TLS=true in production")
	}
	if err := validateProductionRuntimeFiles(initialized, bindReady); err != nil {
		return err
	}
	if err := validatePolicyModeConsistency(); err != nil {
		return err
	}
	if initialized && bindReady && configuredPolicyMode() == "global" && globalDenySetupDeferred() && !platformFirstOnboardingPending() {
		return fmt.Errorf("RPZ_GLOBAL_DENY_SETUP_DEFERRED 仅用于首次初始化；请先完成白名单发布和同步，再启用 BIND 全局 DENY 后移除该配置")
	}
	if configuredPolicyMode() == "global" && (!platformFirstOnboardingPending() || !globalDenySetupDeferred()) {
		zone := configuredGlobalDenyZone()
		if zone == "" || !domainPattern.MatchString(zone) {
			return fmt.Errorf("RPZ_GLOBAL_DENY_ZONE must be a valid zone in global default-deny mode")
		}
		if strings.TrimSpace(os.Getenv("RPZ_GLOBAL_DENY_RECURSOR")) == "" || strings.TrimSpace(os.Getenv("RPZ_GLOBAL_DENY_CHECK_NAME")) == "" {
			return fmt.Errorf("RPZ_GLOBAL_DENY_RECURSOR and RPZ_GLOBAL_DENY_CHECK_NAME are required in global default-deny mode")
		}
	}
	return nil
}

func validateProductionRuntimeFiles(requireConfigured ...bool) error {
	requireNodeAndAuth := true
	bindReady := true
	if len(requireConfigured) > 0 {
		requireNodeAndAuth = requireConfigured[0]
	}
	if len(requireConfigured) > 1 {
		bindReady = requireConfigured[1]
	}
	if _, err := exec.LookPath("named-checkzone"); err != nil {
		return fmt.Errorf("named-checkzone is required in production: %w", err)
	}
	files := []struct {
		path  string
		label string
		mode  os.FileMode
	}{
		{authFilePath(), "AUTH_FILE", 0o077},
		{os.Getenv("DNS_NODE_CONFIG_FILE"), "DNS_NODE_CONFIG_FILE", 0},
	}
	for _, item := range files {
		if !requireNodeAndAuth && item.label != "AUTH_FILE" && item.label != "DNS_NODE_CONFIG_FILE" {
			continue
		}
		if !requireNodeAndAuth {
			continue
		}
		if item.path == "" {
			return fmt.Errorf("%s must be configured in production", item.label)
		}
		info, err := os.Stat(item.path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be an existing regular file: %s", item.label, item.path)
		}
		if item.mode != 0 && info.Mode().Perm()&item.mode != 0 {
			return fmt.Errorf("%s must not be group/world accessible: %s", item.label, item.path)
		}
	}
	if os.Getenv("TLS_CERT_FILE") != "" {
		for _, path := range []string{os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")} {
			info, err := os.Stat(path) // #nosec G703 -- TLS paths are administrator-controlled deployment configuration.
			if err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("TLS file must be an existing regular file: %s", path)
			}
		}
	}
	for _, path := range []string{os.Getenv("DNS_STATE_FILE"), os.Getenv("AUDIT_FILE"), os.Getenv("RPZ_ARTIFACT_FILE"), os.Getenv("TLD_STATE_FILE"), os.Getenv("TLD_DENY_ARTIFACT_FILE")} {
		if path == "" {
			continue
		}
		parent := filepath.Dir(path)
		info, err := os.Stat(parent) // #nosec G703 -- runtime paths are administrator-controlled deployment configuration.
		if err != nil || !info.IsDir() {
			return fmt.Errorf("runtime data directory does not exist: %s", parent)
		}
		if info.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("runtime data directory must not be world writable: %s", parent)
		}
	}
	if rpzConfig("RPZ_PUBLISH_MODE", "artifact") == "nsupdate" && (bindReady || !platformBootstrapEnabled()) {
		keyFile := os.Getenv("RPZ_KEY_FILE")
		info, err := os.Stat(keyFile) // #nosec G703 -- RPZ_KEY_FILE is a protected administrator-controlled path.
		if keyFile == "" || err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("RPZ_KEY_FILE must be an existing regular file in nsupdate mode")
		}
		if info.Mode().Perm()&0o007 != 0 {
			return fmt.Errorf("RPZ_KEY_FILE must not be world accessible")
		}
	}
	if tldPolicyPublishEnabled() {
		if tldPolicyZone() == "" {
			return fmt.Errorf("TLD_DENY_ZONE must be configured when TLD_DENY_PUBLISH_ENABLED=true")
		}
		if !domainPattern.MatchString(tldPolicyZone()) {
			return fmt.Errorf("TLD_DENY_ZONE is invalid")
		}
		if os.Getenv("RPZ_PRIMARY") == "" {
			return fmt.Errorf("RPZ_PRIMARY must be configured when TLD DENY publishing is enabled")
		}
		keyFile := os.Getenv("RPZ_KEY_FILE")
		info, err := os.Stat(keyFile)
		if keyFile == "" || err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 {
			return fmt.Errorf("RPZ_KEY_FILE must be a protected regular file for TLD DENY publishing")
		}
	}
	return nil
}
