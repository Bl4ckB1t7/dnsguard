package main

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type captchaEntry struct {
	Code    string
	Expires time.Time
}

var captchaMu sync.Mutex
var captchas = map[string]captchaEntry{}

const captchaChars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

func randomCaptcha(size int) string {
	result := make([]byte, size)
	random := make([]byte, size)
	if _, err := rand.Read(random); err != nil {
		return "7K4M"
	}
	for index := range result {
		result[index] = captchaChars[int(random[index])%len(captchaChars)]
	}
	return string(result)
}

func captchaSVG(code string) string {
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="148" height="42" viewBox="0 0 148 42"><rect width="148" height="42" rx="4" fill="#041b30"/><path d="M8 31L138 9M5 10L135 34M30 4L117 39" stroke="#1d7a98" stroke-width="1" opacity=".7"/><circle cx="19" cy="12" r="2" fill="#53e9ff"/><circle cx="128" cy="29" r="2" fill="#53e9ff"/><text x="74" y="29" text-anchor="middle" fill="#c9fbff" font-family="Arial,sans-serif" font-size="23" font-weight="700" letter-spacing="6">%s</text></svg>`, code)
}

func captcha(w http.ResponseWriter, _ *http.Request) {
	id := randomCaptcha(18)
	code := randomCaptcha(4)
	captchaMu.Lock()
	for key, entry := range captchas {
		if time.Now().After(entry.Expires) {
			delete(captchas, key)
		}
	}
	captchas[id] = captchaEntry{Code: code, Expires: time.Now().Add(5 * time.Minute)}
	captchaMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "svg": captchaSVG(code), "expiresIn": "300"})
}

func validateCaptcha(id, code string) bool {
	captchaMu.Lock()
	defer captchaMu.Unlock()
	entry, ok := captchas[id]
	if ok {
		delete(captchas, id)
	}
	return ok && time.Now().Before(entry.Expires) && strings.EqualFold(strings.TrimSpace(code), entry.Code)
}
