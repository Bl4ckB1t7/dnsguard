package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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
		"title":    "DNS 解析控制中心",
		"subtitle": "BIND 集群与 RPZ 策略管理平台",
	})
}

func main() {
	if err := validateSecurityConfig(); err != nil {
		log.Fatal(err)
	}
	loadDNSState()
	loadAudit()
	loadAuth()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", health)
	mux.HandleFunc("/api/settings", settings)
	mux.HandleFunc("/api/auth/login", authLogin)
	mux.HandleFunc("/api/auth/captcha", captcha)
	mux.HandleFunc("/api/auth/me", authMe)
	mux.HandleFunc("/api/auth/logout", authLogout)
	mux.HandleFunc("/api/auth/password", authPasswordChange)
	mux.HandleFunc("/api/dns/overview", dnsOverview)
	mux.HandleFunc("/api/dns/nodes", dnsNodes)
	mux.HandleFunc("/api/dns/records", dnsRecords)
	mux.HandleFunc("/api/dns/rpz", dnsRules)
	mux.HandleFunc("/api/dns/rpz/publish", publishRPZ)
	mux.HandleFunc("/api/dns/rpz/", dnsRuleByID)
	mux.HandleFunc("/api/audit", audit)

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8080"
	}
	server := &http.Server{Addr: listenAddr, Handler: authMiddleware(mux), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("dns ops API listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func validateSecurityConfig() error {
	if os.Getenv("APP_ENV") != "production" {
		return nil
	}
	if os.Getenv("AUTH_PASSWORD") == "" || os.Getenv("AUTH_PASSWORD") == "admin" || os.Getenv("AUTH_PASSWORD") == "change-me" {
		return fmt.Errorf("AUTH_PASSWORD must be changed in production")
	}
	if len(os.Getenv("AUTH_SECRET")) < 32 {
		return fmt.Errorf("AUTH_SECRET must be at least 32 characters in production")
	}
	return nil
}
