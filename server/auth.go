package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookie = "network_session"
const csrfCookie = "network_csrf"

func authEnabled() bool {
	value := strings.TrimSpace(os.Getenv("AUTH_ENABLED"))
	if value == "" {
		return true
	}
	enabled, err := strconv.ParseBool(value)
	return err != nil || enabled
}

type authStore struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
}

var storedAuth authStore
var authMu sync.RWMutex
var activeSessions = map[string]string{}

type authAttempt struct {
	Failures int
	Since    time.Time
	Blocked  time.Time
}

var authAttemptsMu sync.Mutex
var authAttempts = map[string]authAttempt{}

func authUsername() string {
	if value := os.Getenv("AUTH_USERNAME"); value != "" {
		return value
	}
	return "admin"
}

func authPassword() string {
	return ""
}

func authSecret() []byte {
	if value := os.Getenv("AUTH_SECRET"); value != "" {
		return []byte(value)
	}
	return []byte("change-this-network-visualizer-secret")
}

func authFilePath() string {
	if value := os.Getenv("AUTH_FILE"); value != "" {
		return value
	}
	return "auth.json"
}

func passwordDigest(password string) string {
	hash := hmac.New(sha256.New, authSecret())
	_, _ = hash.Write([]byte(password))
	return base64.RawStdEncoding.EncodeToString(hash.Sum(nil))
}

func loadAuth() {
	content, err := os.ReadFile(authFilePath())
	if err == nil {
		var loaded authStore
		if json.Unmarshal(content, &loaded) == nil {
			authMu.Lock()
			storedAuth = loaded
			authMu.Unlock()
		}
	}
}

func authFileHasPasswordHash() bool {
	content, err := os.ReadFile(authFilePath())
	if err != nil {
		return false
	}
	var loaded authStore
	return json.Unmarshal(content, &loaded) == nil && strings.HasPrefix(loaded.PasswordHash, "$2")
}

func passwordValid(username, password string) bool {
	if username != authUsername() {
		return false
	}
	authMu.RLock()
	hash := storedAuth.PasswordHash
	authMu.RUnlock()
	if hash != "" {
		if strings.HasPrefix(hash, "$2") {
			return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
		}
		return hmac.Equal([]byte(hash), []byte(passwordDigest(password)))
	}
	return false
}

func newSessionID() string {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return passwordDigest(strconv.FormatInt(time.Now().UnixNano(), 10))
	}
	return base64.RawURLEncoding.EncodeToString(buffer)
}

func newCSRFToken() string {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return passwordDigest(strconv.FormatInt(time.Now().UnixNano(), 10))
	}
	return base64.RawURLEncoding.EncodeToString(buffer)
}

func signSession(username string, expiry int64, sessionID string) string {
	payload := username + "." + strconv.FormatInt(expiry, 10) + "." + sessionRevision() + "." + sessionID
	hash := hmac.New(sha256.New, authSecret())
	_, _ = hash.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "." + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))))
}

func validSession(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return false
	}
	parts := strings.Split(string(decoded), ".")
	if len(parts) != 5 || parts[0] == "" || parts[3] == "" {
		return false
	}
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return false
	}
	if parts[2] != sessionRevision() {
		return false
	}
	authMu.RLock()
	activeSession := activeSessions[parts[0]]
	authMu.RUnlock()
	if activeSession == "" || activeSession != parts[3] {
		return false
	}
	expected := signSession(parts[0], expiry, parts[3])
	return hmac.Equal([]byte(value), []byte(expected))
}

func authMe(w http.ResponseWriter, r *http.Request) {
	if !authEnabled() {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "authEnabled": false, "username": authUsername()})
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || !validSession(cookie.Value) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "username": authUsername()})
}

func authLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var credentials struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		CaptchaID string `json:"captchaId"`
		Captcha   string `json:"captcha"`
	}
	ip := requestIP(r)
	if retryAfter, blocked := authRateLimited(ip); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "登录尝试过于频繁，请稍后再试"})
		return
	}
	if readJSONError := decodeJSON(r, &credentials); readJSONError != nil || !validateCaptcha(credentials.CaptchaID, credentials.Captcha) || !passwordValid(credentials.Username, credentials.Password) {
		recordAuthFailure(ip)
		auditEvent(r, credentials.Username, "login", "failure")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "用户名、密码或验证码错误"})
		return
	}
	clearAuthFailures(ip)
	expiry := time.Now().Add(8 * time.Hour).Unix()
	sessionID := newSessionID()
	authMu.Lock()
	activeSessions[credentials.Username] = sessionID
	authMu.Unlock()
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: signSession(credentials.Username, expiry, sessionID), Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 8 * 60 * 60})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: newCSRFToken(), Path: "/", Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 8 * 60 * 60})
	auditEvent(r, credentials.Username, "login", "success")
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "username": credentials.Username})
}

func requestIP(r *http.Request) string {
	if os.Getenv("TRUST_PROXY_HEADERS") == "true" {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
			return forwarded
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func authRateLimited(ip string) (int, bool) {
	now := time.Now()
	authAttemptsMu.Lock()
	defer authAttemptsMu.Unlock()
	attempt := authAttempts[ip]
	if !attempt.Blocked.IsZero() && now.Before(attempt.Blocked) {
		return int(time.Until(attempt.Blocked).Seconds()) + 1, true
	}
	if !attempt.Since.IsZero() && now.Sub(attempt.Since) > 5*time.Minute {
		delete(authAttempts, ip)
	}
	return 0, false
}

func recordAuthFailure(ip string) {
	now := time.Now()
	authAttemptsMu.Lock()
	defer authAttemptsMu.Unlock()
	attempt := authAttempts[ip]
	if attempt.Since.IsZero() || now.Sub(attempt.Since) > 5*time.Minute {
		attempt = authAttempt{Since: now}
	}
	attempt.Failures++
	if attempt.Failures >= 5 {
		attempt.Blocked = now.Add(5 * time.Minute)
	}
	authAttempts[ip] = attempt
	if len(authAttempts) > 10000 {
		for key, value := range authAttempts {
			if value.Since.IsZero() || now.Sub(value.Since) > 5*time.Minute {
				delete(authAttempts, key)
			}
		}
	}
}

func clearAuthFailures(ip string) {
	authAttemptsMu.Lock()
	delete(authAttempts, ip)
	authAttemptsMu.Unlock()
}

func saveAuthFile(updated authStore) error {
	content, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		return err
	}
	path := authFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".auth-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func authPasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var request struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := decodeJSON(r, &request); err != nil || !passwordValid(authUsername(), request.CurrentPassword) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "当前密码不正确"})
		return
	}
	if len(request.NewPassword) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "新密码至少需要 8 位"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "密码加密失败"})
		return
	}
	authMu.Lock()
	updatedAuth := authStore{Username: authUsername(), PasswordHash: string(hash)}
	authMu.Unlock()
	if err := saveAuthFile(updatedAuth); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "密码保存失败"})
		return
	}
	authMu.Lock()
	storedAuth = updatedAuth
	delete(activeSessions, updatedAuth.Username)
	authMu.Unlock()
	auditEvent(r, updatedAuth.Username, "password.change", "success")
	writeJSON(w, http.StatusOK, map[string]bool{"changed": true})
}

func sessionRevision() string {
	authMu.RLock()
	revision := storedAuth.PasswordHash
	authMu.RUnlock()
	if revision == "" {
		revision = passwordDigest(authPassword())
	}
	hash := sha256.Sum256([]byte(revision))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func authLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !authEnabled() {
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
		return
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil && validSession(cookie.Value) {
		if decoded, decodeErr := base64.RawURLEncoding.DecodeString(cookie.Value); decodeErr == nil {
			parts := strings.Split(string(decoded), ".")
			if len(parts) == 5 {
				authMu.Lock()
				if activeSessions[parts[0]] == parts[3] {
					delete(activeSessions, parts[0])
				}
				authMu.Unlock()
			}
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1, Expires: time.Unix(1, 0), SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), SameSite: http.SameSiteLaxMode})
	auditEvent(r, authUsername(), "logout", "success")
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, r)
		setCORSHeaders(w, r)
		if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		if !authEnabled() {
			next.ServeHTTP(w, r)
			return
		}
		public := r.URL.Path == "/api/health" || r.URL.Path == "/api/monitoring/status" || (r.URL.Path == "/api/settings" && r.Method == http.MethodGet) || r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/captcha" || r.URL.Path == "/api/auth/me" || r.URL.Path == "/api/auth/logout" || r.Method == http.MethodOptions
		if public {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(sessionCookie)
		if err != nil || !validSession(cookie.Value) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !csrfValid(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf token required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	secure := r.TLS != nil || (os.Getenv("TRUST_PROXY_TLS") == "true" && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
	if secure {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

func monitoringTokenValid(r *http.Request) bool {
	expected := strings.TrimSpace(os.Getenv("MONITORING_TOKEN"))
	if expected != "" {
		const prefix = "Bearer "
		provided := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(provided, prefix) {
			return false
		}
		provided = strings.TrimSpace(strings.TrimPrefix(provided, prefix))
		return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func csrfValid(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	return header != "" && hmac.Equal([]byte(cookie.Value), []byte(header))
}

func allowedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	configured := strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")
	for _, candidate := range configured {
		if strings.TrimSpace(candidate) == origin {
			return true
		}
	}
	return origin == "http://127.0.0.1:5173" || origin == "http://127.0.0.1:5174" || origin == "http://localhost:5173"
}

func setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if allowedOrigin(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
	}
}
