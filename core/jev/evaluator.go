// Semantic evaluator interface (spec 16.1) and evaluator implementations.
package jev

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"offense.dev/raid/core/canonical"
)

// SemanticInput is the allowlisted input to the evaluator.
type SemanticInput struct {
	State string
	// Ceiling is the maximum escalation the policy permits:
	// "" (require_approval only) or "deny".
	Ceiling string
}

// SemanticEvaluator is implemented by both the HTTP adapter and the fake.
type SemanticEvaluator interface {
	// Evaluate returns the semantic judgment; failures surface as errors
	// so the caller applies the configured failure effect.
	Evaluate(in SemanticInput) (*SemanticResult, error)
}

// --- Fake evaluator (tests and demo) ---

type fakeEvaluator struct {
	answers    map[string]Answer
	thresholds Thresholds
	err        error
	model      string
	calls      atomic.Value
}

// NewFakeEvaluator returns a scripted evaluator.
func NewFakeEvaluator(answers map[string]Answer, thresholds Thresholds, err error) SemanticEvaluator {
	return &fakeEvaluator{answers: answers, thresholds: thresholds, err: err, model: "jev-1.13.0"}
}

// CallCount reports how many times the fake was invoked (J01/J02).
func Calls(e SemanticEvaluator) int64 {
	f, ok := e.(*fakeEvaluator)
	if !ok {
		return -1
	}
	if v := f.calls.Load(); v != nil {
		n, _ := v.(int64)
		return n
	}
	return 0
}

func (f *fakeEvaluator) Evaluate(in SemanticInput) (*SemanticResult, error) {
	n := int64(0)
	if v := f.calls.Load(); v != nil {
		n, _ = v.(int64)
	}
	f.calls.Store(n + 1)
	if f.err != nil {
		return nil, f.err
	}
	esc := f.thresholds.DecideEscalation(f.answers, in.Ceiling)
	return &SemanticResult{
		Escalation: esc,
		Model: f.model, QuestionSet: QuestionSet,
		LatencyMs: 4,
		Answers:  EvidenceJSON(f.answers),
	}, nil
}

// --- HTTP evaluator (spec 7.4 / 7.9) ---
//
// The production adapter POSTs the allowlisted state and pinned question set
// to TypeSafe System One. Unit tests exercise all invariants through the
// fake evaluator (J01-J12); live-service behavior is an integration concern
// for the hosted deployment.

type httpEvaluator struct {
	endpoint string
	apiKey   string
	model    string
	deadlineNs int64
}

// NewHttpEvaluator wires the HTTP adapter.
func NewHttpEvaluator(endpoint, apiKey, model string, deadlineNs int64) SemanticEvaluator {
	if endpoint == "" {
		endpoint = "https://api.typesafe.ai/v1/systemone"
	}
	if model == "" {
		model = "jev-1.13.0"
	}
	return &httpEvaluator{endpoint: endpoint, apiKey: apiKey, model: model, deadlineNs: deadlineNs}
}

// HttpClient is the injectable HTTP send function (testable without network).
type HttpClient interface {
	PostJSON(url, apiKey string, body []byte, deadlineNs int64) (int, []byte, error)
}

var globalClient HttpClient

// SetHttpClient installs a transport (defaults to the network client).
func SetHttpClient(c HttpClient) () { globalClient = c }

func (f *httpEvaluator) Evaluate(in SemanticInput) (*SemanticResult, error) {
	body := BodyForRequest(in.State)
	client := globalClient
	if client == nil {
		client = &netClient{}
	}
	status, resp, err := client.PostJSON(f.endpoint, f.apiKey, []byte(body), f.deadlineNs)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, errors.New("raid: jev http status " + strconv.FormatInt(int64(status), 10))
	}
	// Response schema: {model, answers: {id: {choice, probability}}}
	answers, aerr := decodeAnswers(resp)
	if aerr != nil {
		return nil, aerr
	}
	latency := int64(f.deadlineNs / int64(time.Millisecond))
	return &SemanticResult{
		Model: f.model, QuestionSet: QuestionSet,
		LatencyMs: latency, Answers: EvidenceJSON(answers),
	}, nil
}

// decodeAnswers parses the System One answers map against the documented
// schema (spec 7.4): {model, answers: {id: {choice?, probability?, score?}}}.
// Failures surface as errors so the caller escalates (spec 7.7).
func decodeAnswers(resp []byte) (map[string]Answer, error) {
	out := map[string]Answer{}
	v, perr := canonical.Decode(resp, canonical.DecodeOptions{MaxBytes: 1 * 1024 * 1024})
	if perr != nil {
		return out, errors.New("raid: jev invalid json")
	}
	if v.Kind() != canonical.VObject {
		return out, errors.New("raid: jev response is not an object")
	}
	ans, ok := v.AsMap()["answers"]
	if !ok || ans.Kind() != canonical.VObject {
		return out, errors.New("raid: jev response missing answers")
	}
	for id, av := range ans.AsMap() {
		if av.Kind() != canonical.VObject {
			continue
		}
		m := av.AsMap()
		var a Answer
		if choice, ok := m["choice"]; ok && choice.Kind() == canonical.VString {
			a.Choice = choice.AsString()
		}
		prob, ok := m["probability"]
		if !ok {
			prob, ok = m["score"]
		}
		if !ok || (prob.Kind() != canonical.VInt64 && prob.Kind() != canonical.VUint64 && prob.Kind() != canonical.VDecimal) {
			continue // missing/invalid probability: answer invalid
		}
		a.Score = numToFloat(prob)
		a.Valid = true
		out[id] = a
	}
	return out, nil
}

func numToFloat(v canonical.Value) float64 {
	switch v.Kind() {
	case canonical.VInt64:
		return float64(v.AsInt())
	case canonical.VUint64:
		return float64(v.AsUint())
	case canonical.VDecimal:
		f, _ := strconv.ParseFloat(v.AsString(), 64)
		return f
	}
	return 0
}

// --- circuit breaker (spec 15.4) ---

type CircuitState int

const (
	CircuitClosed CircuitState = 0
	CircuitOpen   CircuitState = 1
	CircuitHalf   CircuitState = 2
)

type CircuitBreaker struct {
	failures atomic.Value
	state    atomic.Value
	openedAt atomic.Value
	threshold int64
}

// NewCircuitBreaker tracks consecutive failures; opens at threshold.
func NewCircuitBreaker(threshold int64) *CircuitBreaker {
	return &CircuitBreaker{threshold: threshold}
}

// RecordFailure increments the counter; opens at threshold.
func (c *CircuitBreaker) RecordFailure(now time.Time) bool {
	n := int64(0)
	if v := c.failures.Load(); v != nil {
		n, _ = v.(int64)
	}
	n++
	c.failures.Store(n)
	if n >= c.threshold {
		c.state.Store(int64(CircuitOpen))
		c.openedAt.Store(now.UnixNano())
		return true
	}
	return false
}

// RecordSuccess resets the breaker.
func (c *CircuitBreaker) RecordSuccess() () {
	c.failures.Store(int64(0))
	c.state.Store(int64(CircuitClosed))
}

// IsOpen reports whether the breaker short-circuits (30s trial window).
func (c *CircuitBreaker) IsOpen(now time.Time) bool {
	var st int64
	if v := c.state.Load(); v != nil {
		st, _ = v.(int64)
	}
	if st != int64(CircuitOpen) {
		return false
	}
	var opened int64
	if v := c.openedAt.Load(); v != nil {
		opened, _ = v.(int64)
	}
	if now.UnixNano() - opened > 30_000_000_000 {
		c.state.Store(int64(CircuitHalf))
		return false
	}
	return true
}

// netClient is the default network transport: a real HTTPS POST with a bounded
// deadline and response size. It fails closed (returns an error) on any
// transport or read failure so the caller applies the configured failure
// effect; the API key is only ever sent to the configured endpoint.
type netClient struct{}

// maxTransportBytes caps a Jev response body read (defensive).
const maxTransportBytes = int64(4 << 20)

func (n *netClient) PostJSON(url, apiKey string, body []byte, deadlineNs int64) (int, []byte, error) {
	if deadlineNs <= 0 {
		deadlineNs = 650 * int64(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deadlineNs))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("raid: jev request: " + err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, errors.New("raid: jev transport: " + err.Error())
	}
	defer resp.Body.Close()
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxTransportBytes))
	if rerr != nil {
		return 0, nil, errors.New("raid: jev read: " + rerr.Error())
	}
	return resp.StatusCode, data, nil
}

// SemanticExecutor applies the spec 7.6 escalation strategy on top of a
// base decision (used by decision.Engine through the evaluator interface).
func SemanticEscalation(baseEffect, guardEscalation string, result *SemanticResult) string {
	if result == nil {
		return baseEffect
	}
	if result.Escalation == "" {
		return baseEffect
	}
	return combine(baseEffect, result.Escalation)
}