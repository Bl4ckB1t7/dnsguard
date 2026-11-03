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

type captchaRequest struct {
	Count   int
	Started time.Time
}

var captchaMu sync.Mutex
var captchas = map[string]captchaEntry{}
var captchaRateMu sync.Mutex
var captchaRates = map[string]captchaRequest{}

const captchaChars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
const maxCaptchas = 10000
const captchaRateWindow = time.Minute
const captchaRateLimit = 10

var captchaGlyphs = map[byte][7]string{
	'0': {"01110", "10001", "10011", "10101", "11001", "10001", "01110"}, '1': {"00100", "01100", "00100", "00100", "00100", "00100", "01110"}, '2': {"01110", "10001", "00001", "00010", "00100", "01000", "11111"}, '3': {"11110", "00001", "00001", "01110", "00001", "00001", "11110"}, '4': {"00010", "00110", "01010", "10010", "11111", "00010", "00010"}, '5': {"11111", "10000", "10000", "11110", "00001", "00001", "11110"}, '6': {"01110", "10000", "10000", "11110", "10001", "10001", "01110"}, '7': {"11111", "00001", "00010", "00100", "01000", "01000", "01000"}, '8': {"01110", "10001", "10001", "01110", "10001", "10001", "01110"}, '9': {"01110", "10001", "10001", "01111", "00001", "00001", "01110"},
	'A': {"01110", "10001", "10001", "11111", "10001", "10001", "10001"}, 'B': {"11110", "10001", "10001", "11110", "10001", "10001", "11110"}, 'C': {"01111", "10000", "10000", "10000", "10000", "10000", "01111"}, 'D': {"11110", "10001", "10001", "10001", "10001", "10001", "11110"}, 'E': {"11111", "10000", "10000", "11110", "10000", "10000", "11111"}, 'F': {"11111", "10000", "10000", "11110", "10000", "10000", "10000"}, 'G': {"01111", "10000", "10000", "10111", "10001", "10001", "01110"}, 'H': {"10001", "10001", "10001", "11111", "10001", "10001", "10001"}, 'J': {"00111", "00010", "00010", "00010", "10010", "10010", "01100"}, 'K': {"10001", "10010", "10100", "11000", "10100", "10010", "10001"}, 'L': {"10000", "10000", "10000", "10000", "10000", "10000", "11111"}, 'M': {"10001", "11011", "10101", "10101", "10001", "10001", "10001"}, 'N': {"10001", "11001", "10101", "10011", "10001", "10001", "10001"}, 'P': {"11110", "10001", "10001", "11110", "10000", "10000", "10000"}, 'Q': {"01110", "10001", "10001", "10001", "10101", "10010", "01101"}, 'R': {"11110", "10001", "10001", "11110", "10100", "10010", "10001"}, 'S': {"01111", "10000", "10000", "01110", "00001", "00001", "11110"}, 'T': {"11111", "00100", "00100", "00100", "00100", "00100", "00100"}, 'U': {"10001", "10001", "10001", "10001", "10001", "10001", "01110"}, 'V': {"10001", "10001", "10001", "10001", "10001", "01010", "00100"}, 'W': {"10001", "10001", "10001", "10101", "10101", "11011", "10001"}, 'X': {"10001", "10001", "01010", "00100", "01010", "10001", "10001"}, 'Y': {"10001", "10001", "01010", "00100", "00100", "00100", "00100"}, 'Z': {"11111", "00001", "00010", "00100", "01000", "10000", "11111"},
}

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
	var builder strings.Builder
	builder.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="148" height="42" viewBox="0 0 148 42"><rect width="148" height="42" rx="4" fill="#041b30"/><path d="M8 31L138 9M5 10L135 34M30 4L117 39" stroke="#1d7a98" stroke-width="1" opacity=".7"/><circle cx="19" cy="12" r="2" fill="#53e9ff"/><circle cx="128" cy="29" r="2" fill="#53e9ff"/>`)
	for index := 0; index < len(code); index++ {
		glyph, ok := captchaGlyphs[code[index]]
		if !ok {
			continue
		}
		for row, pattern := range glyph {
			for column, pixel := range pattern {
				if pixel == '1' {
					fmt.Fprintf(&builder, `<rect x="%d" y="%d" width="3" height="3" rx=".5" fill="#c9fbff"/>`, 39+index*18+column*3, 8+row*4)
				}
			}
		}
	}
	builder.WriteString(`</svg>`)
	return builder.String()
}

func captcha(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	now := time.Now()
	captchaRateMu.Lock()
	rate := captchaRates[ip]
	if rate.Started.IsZero() || now.Sub(rate.Started) >= captchaRateWindow {
		rate = captchaRequest{Started: now}
	}
	rate.Count++
	captchaRates[ip] = rate
	blocked := rate.Count > captchaRateLimit
	if len(captchaRates) > 10000 {
		for key, value := range captchaRates {
			if now.Sub(value.Started) >= captchaRateWindow {
				delete(captchaRates, key)
			}
		}
	}
	captchaRateMu.Unlock()
	if blocked {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "验证码请求过于频繁，请稍后再试"})
		return
	}
	id := randomCaptcha(18)
	code := randomCaptcha(4)
	captchaMu.Lock()
	for key, entry := range captchas {
		if now.After(entry.Expires) {
			delete(captchas, key)
		}
	}
	if len(captchas) >= maxCaptchas {
		oldestKey := ""
		oldestExpiry := time.Time{}
		for key, entry := range captchas {
			if oldestKey == "" || entry.Expires.Before(oldestExpiry) {
				oldestKey, oldestExpiry = key, entry.Expires
			}
		}
		if oldestKey != "" {
			delete(captchas, oldestKey)
		}
	}
	captchas[id] = captchaEntry{Code: code, Expires: time.Now().Add(5 * time.Minute)}
	captchaMu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
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
