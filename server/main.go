package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	writeJSON(w, http.StatusOK, Health{Status: "ok", Service: "dns-ops-api", Time: time.Now().UTC().Format(time.RFC3339)})
}

func settings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"title":    "域盾 DNSGuard",
		"subtitle": "企业 DNS 安全运维平台",
	})
}

func main() {
	if err := validateSecurityConfig(); err != nil {
		log.Fatal(err)
	}
	loadDNSState()
	if err := loadDNSNodeConfig(); err != nil {
		log.Fatal(err)
	}
	loadAudit()
	loadAuth()
	startDNSHealthMonitor()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", health)
	mux.HandleFunc("/api/monitoring/status", monitoringStatus)
	mux.HandleFunc("/api/settings", settings)
	mux.HandleFunc("/api/auth/login", authLogin)
	mux.HandleFunc("/api/auth/captcha", captcha)
	mux.HandleFunc("/api/auth/me", authMe)
	mux.HandleFunc("/api/auth/logout", authLogout)
	mux.HandleFunc("/api/auth/password", authPasswordChange)
	mux.HandleFunc("/api/dns/overview", dnsOverview)
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
	server := &http.Server{Addr: listenAddr, Handler: authMiddleware(mux), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("dns ops API listening on %s", server.Addr)
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile != "" && keyFile != "" {
		log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
	}
	log.Fatal(server.ListenAndServe())
}

func validateSecurityConfig() error {
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
	if !authFileHasPasswordHash() {
		return fmt.Errorf("AUTH_FILE must contain a bcrypt password hash; run scripts/create-auth-file.sh")
	}
	if (os.Getenv("TLS_CERT_FILE") == "" || os.Getenv("TLS_KEY_FILE") == "") && os.Getenv("TRUST_PROXY_TLS") != "true" {
		return fmt.Errorf("configure TLS_CERT_FILE/TLS_KEY_FILE or set TRUST_PROXY_TLS=true in production")
	}
	if err := validateProductionRuntimeFiles(); err != nil {
		return err
	}
	return nil
}

func validateProductionRuntimeFiles() error {
	if _, err := exec.LookPath("named-checkzone"); err != nil {
		return fmt.Errorf("named-checkzone is required in production: %w", err)
	}
	for _, item := range []struct {
		path  string
		label string
		mode  os.FileMode
	}{
		{authFilePath(), "AUTH_FILE", 0o077},
		{os.Getenv("DNS_NODE_CONFIG_FILE"), "DNS_NODE_CONFIG_FILE", 0},
	} {
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
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("TLS file must be an existing regular file: %s", path)
			}
		}
	}
	for _, path := range []string{os.Getenv("DNS_STATE_FILE"), os.Getenv("AUDIT_FILE"), os.Getenv("RPZ_ARTIFACT_FILE")} {
		if path == "" {
			continue
		}
		parent := filepath.Dir(path)
		info, err := os.Stat(parent)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("runtime data directory does not exist: %s", parent)
		}
		if info.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("runtime data directory must not be world writable: %s", parent)
		}
	}
	if rpzConfig("RPZ_PUBLISH_MODE", "artifact") == "nsupdate" {
		keyFile := os.Getenv("RPZ_KEY_FILE")
		info, err := os.Stat(keyFile)
		if keyFile == "" || err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("RPZ_KEY_FILE must be an existing regular file in nsupdate mode")
		}
		if info.Mode().Perm()&0o007 != 0 {
			return fmt.Errorf("RPZ_KEY_FILE must not be world accessible")
		}
	}
	return nil
}
