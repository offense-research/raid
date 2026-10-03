// Unit tests for the network-facing middleware (internal: exercises the
// unexported tokenAuth / rateLimiter directly).
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

func do(h http.Handler, setHeader func(*http.Request)) int {
	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	if setHeader != nil {
		setHeader(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestTokenAuthMiddleware(t *testing.T) {
	h := tokenAuth(okHandler(), "s3cret")

	if got := do(h, nil); got != http.StatusUnauthorized {
		t.Errorf("missing token: got %d want 401", got)
	}
	if got := do(h, func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }); got != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d want 401", got)
	}
	if got := do(h, func(r *http.Request) { r.Header.Set("Authorization", "Bearer s3cret") }); got != http.StatusOK {
		t.Errorf("bearer token: got %d want 200", got)
	}
	if got := do(h, func(r *http.Request) { r.Header.Set("X-Raid-Token", "s3cret") }); got != http.StatusOK {
		t.Errorf("header token: got %d want 200", got)
	}
}

func TestRateLimiterMiddleware(t *testing.T) {
	h := newRateLimiter(1, 2).wrap(okHandler())
	if got := do(h, nil); got != http.StatusOK {
		t.Errorf("first request: got %d want 200", got)
	}
	if got := do(h, nil); got != http.StatusOK {
		t.Errorf("second request (burst): got %d want 200", got)
	}
	if got := do(h, nil); got != http.StatusTooManyRequests {
		t.Errorf("third request: got %d want 429", got)
	}
}

func TestRateLimiterRefills(t *testing.T) {
	l := newRateLimiter(1000, 1)
	t0 := time.Now()
	if !l.allow(t0) {
		t.Fatal("first allow should pass")
	}
	if l.allow(t0) {
		t.Error("second allow with no elapsed time should fail")
	}
	if !l.allow(t0.Add(2 * time.Second)) { // 1000/s refills the burst
		t.Error("allow should pass after refill")
	}
}
