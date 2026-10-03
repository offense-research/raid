// Network-facing middleware for the TCP listener: bearer-token auth and a
// global token-bucket rate limit. The Unix socket is authenticated by peer
// UID and does not use these.
package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"
)

// tokenAuth enforces a bearer token, accepted via either
// `Authorization: Bearer <token>` or `X-Raid-Token: <token>`.
func tokenAuth(next http.Handler, token string) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(bearerToken(r)), want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(errDoc(CodeUnauthorized, "invalid or missing token", false, "")))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	if v := r.Header.Get("X-Raid-Token"); v != "" {
		return v
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// rateLimiter is a global token bucket over a network-facing handler.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newRateLimiter(perSec float64, burst int) *rateLimiter {
	if burst <= 0 {
		burst = int(perSec)
	}
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{rate: perSec, burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

func (l *rateLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	l.last = now
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

func (l *rateLimiter) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(time.Now()) {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(errDoc(CodeUnavailable, "rate limit exceeded", true, "")))
			return
		}
		next.ServeHTTP(w, r)
	})
}
