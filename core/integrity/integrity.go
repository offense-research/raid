// Package integrity implements the intermediary-integrity contract described in
// docs/threat-model.md (RAID-SEC-016..019).
//
// It is the deterministic, dependency-free half of Raid's defense against
// malicious LLM-router / intermediary attacks on the supply chain
// (arXiv:2604.08407, "Your Agent Is Mine"). A client sits behind a chain of
// routers; each hop terminates and re-originates TLS, so each sees every
// in-flight JSON payload. Nothing in the deployed stack binds the tool-call
// arguments the provider returned to the arguments the client finally executes,
// so any single hop can rewrite a call (AC-1), inject a call the model never
// made, or reorder a sequence of calls (AC-1.a/AC-1.b).
//
// The package classifies two things and nothing else:
//
//   - Provenance: which host produced the response, whether that host is the
//     provider's own endpoint or an intermediary hop, and whether the provider
//     and model the response claims match the ones requested.
//   - Tool-call integrity: whether a call about to run is one the model
//     declared, whether its arguments still match what was declared, and
//     whether it arrived in the order the model declared.
//
// It decides nothing. Like every Raid classifier it only supplies conclusions
// as resource.attributes strings; the policy bundle decides deterministically
// and fails closed. raidd stays stateless -- the session context a single call
// cannot carry (the declared sequence) belongs to the caller.
//
// Digest is a client-side screening aid. It is deliberately NOT the request
// hash: the wire contract in core/canonical/hash.go is untouched.
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Attribute names emitted on resource.attributes. Every adapter emits all of
// them (defaulting to "false") so one policy bundle reads the same under Raider
// as under the Python adapters.
const (
	AttrProviderVerified   = "provider_verified"
	AttrProviderUnattested = "provider_unattested"
	AttrModelMismatch      = "model_mismatch"
	AttrIntermediary       = "intermediary"
	AttrRouterUntrusted    = "router_untrusted"
	AttrInjectedCall       = "injected_call"
	AttrToolArgsUnverified = "tool_args_unverified"
	AttrSequenceAnomaly    = "sequence_anomaly"
)

// AttributeNames lists every attribute this package emits, for adapters that
// stamp defaults without computing them.
var AttributeNames = []string{
	AttrProviderVerified,
	AttrProviderUnattested,
	AttrModelMismatch,
	AttrIntermediary,
	AttrRouterUntrusted,
	AttrInjectedCall,
	AttrToolArgsUnverified,
	AttrSequenceAnomaly,
}

// HostOf extracts the lowercase host from an endpoint or URL. It accepts a bare
// host, a host:port, and a full URL, and strips the port and any path.
func HostOf(endpoint string) string {
	e := strings.TrimSpace(endpoint)
	if e == "" {
		return ""
	}
	parseable := e
	if !strings.Contains(parseable, "://") {
		parseable = "//" + parseable
	}
	if u, err := url.Parse(parseable); err == nil && u.Host != "" {
		return strings.ToLower(u.Hostname())
	}
	// Fall back to a crude split for values url.Parse refuses.
	e = strings.TrimPrefix(e, "//")
	if i := strings.IndexAny(e, "/?#"); i >= 0 {
		e = e[:i]
	}
	if i := strings.LastIndex(e, ":"); i >= 0 {
		e = e[:i]
	}
	return strings.ToLower(e)
}

// HostMatches reports whether host matches any pattern. A pattern matches the
// host exactly or as a domain suffix, so "anthropic.com" matches
// "api.anthropic.com" but never "notanthropic.com". A leading "*." or "." is
// accepted and ignored, since callers write both.
func HostMatches(host string, patterns []string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		p = strings.TrimPrefix(p, "*.")
		p = strings.TrimPrefix(p, ".")
		if p == "" {
			continue
		}
		if h == p || strings.HasSuffix(h, "."+p) {
			return true
		}
	}
	return false
}

// ClassifyHost reports what an endpoint host is: the provider's own endpoint, a
// flagged intermediary, or an unrecognised hop.
//
// A trusted host is not an intermediary. A listed intermediary is untrusted by
// definition -- that is what the list is for. Anything else is still an
// intermediary hop rather than the provider's own endpoint, but we have not
// flagged it, so it only raises `intermediary`. An empty host is unknown, and
// unknown is not an accusation: it raises neither, and the caller's
// provenance attributes carry the fail-closed verdict instead.
func ClassifyHost(host string, trusted, intermediaries []string) (intermediary, untrusted bool) {
	if strings.TrimSpace(host) == "" {
		return false, false
	}
	if HostMatches(host, trusted) {
		return false, false
	}
	if HostMatches(host, intermediaries) {
		return true, true
	}
	return true, false
}

// Provenance is what the caller observed about the upstream that produced a
// response, against what it asked for.
type Provenance struct {
	// ExpectedProvider and ExpectedModel are what the client requested.
	ExpectedProvider string
	ExpectedModel    string
	// ObservedProvider and ObservedModel are what the response claimed. Empty
	// means the reply carried no usable claim.
	ObservedProvider string
	ObservedModel    string
	// Endpoint is the URL or host the response actually came from.
	Endpoint string
	// TrustedHosts are the provider's own endpoints; IntermediaryHosts are
	// routers known (or configured) to be third-party hops.
	TrustedHosts      []string
	IntermediaryHosts []string
	// Attested is whether the response carried a provider authentication the
	// client could actually verify. It is false whenever the client cannot tell,
	// which is the normal case today: no deployed mechanism signs tool-call
	// arguments.
	Attested bool
}

// Attrs returns the provenance attributes. A response is `provider_verified`
// only when it was attested AND came from a trusted host AND named the
// provider (and model) the client asked for. Everything else is
// `provider_unattested`, so the policy fails closed on an unverifiable
// response rather than treating silence as consent.
func (p Provenance) Attrs() map[string]string {
	host := HostOf(p.Endpoint)
	intermediary, untrusted := ClassifyHost(host, p.TrustedHosts, p.IntermediaryHosts)

	verified := p.Attested &&
		!intermediary &&
		p.ObservedProvider != "" &&
		EqualName(p.ObservedProvider, p.ExpectedProvider) &&
		(p.ObservedModel == "" || p.ExpectedModel == "" ||
			EqualName(p.ObservedModel, p.ExpectedModel))
	mismatch := p.Attested &&
		!intermediary &&
		p.ObservedModel != "" && p.ExpectedModel != "" &&
		!EqualName(p.ObservedModel, p.ExpectedModel)

	return map[string]string{
		AttrProviderVerified:   BoolStr(verified),
		AttrProviderUnattested: BoolStr(!verified),
		AttrModelMismatch:      BoolStr(mismatch),
		AttrIntermediary:       BoolStr(intermediary),
		AttrRouterUntrusted:    BoolStr(untrusted),
	}
}

// Call is one tool call as the client understands it: the tool name and the
// arguments it will run with.
type Call struct {
	Tool string
	Args map[string]any
}

// Fingerprint is the canonical digest of this call.
func (c Call) Fingerprint() string { return Digest(c.Tool, c.Args) }

// Digest returns the canonical SHA-256 digest of a tool call: the lowercased
// tool name and the arguments, encoded as JSON with sorted map keys. It is
// order-independent for the same map contents, so two spellings of one call
// fingerprint identically.
func Digest(tool string, args map[string]any) string {
	payload, err := json.Marshal(struct {
		Tool      string         `json:"tool"`
		Arguments map[string]any `json:"arguments"`
	}{
		Tool:      strings.ToLower(strings.TrimSpace(tool)),
		Arguments: args,
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// EqualTool reports whether two tool names name the same tool.
func EqualTool(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// EqualName reports whether two provider or model names are the same, ignoring
// case and surrounding space.
func EqualName(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// Screen compares the call about to run against the calls the model declared
// for this turn.
//
//   - injected is true when no declared call names this tool at all: the hop
//     invented a call the model never made.
//   - argsUnverified is true when a declared call names the tool but with
//     different arguments: the hop rewrote a call the model did make.
//
// With nothing declared there is nothing to judge against, so both are false:
// the caller that cannot supply the declared set is covered by the provenance
// attributes instead, not by a guess.
func Screen(declared []Call, received Call) (injected, argsUnverified bool) {
	if len(declared) == 0 {
		return false, false
	}
	rf := received.Fingerprint()
	sameTool := false
	for _, d := range declared {
		if !EqualTool(d.Tool, received.Tool) {
			continue
		}
		sameTool = true
		if d.Fingerprint() == rf {
			return false, false
		}
	}
	if sameTool {
		return false, true
	}
	return true, false
}

// ScreenSequence reports whether the call at position index in the declared
// sequence differs from what the model declared there -- a call reordered, or
// one substituted for another. An index outside the declared sequence is not a
// judgement (the caller is running ahead of what it can compare), so it is
// false.
func ScreenSequence(declared []Call, index int, received Call) (sequenceAnomaly bool) {
	if index < 0 || index >= len(declared) {
		return false
	}
	d := declared[index]
	return !EqualTool(d.Tool, received.Tool) || d.Fingerprint() != received.Fingerprint()
}

// CallAttrs screens one call against the declared sequence and returns the
// tool-call-integrity attributes. index is the call's position in the declared
// sequence, or -1 when the caller cannot supply one.
func CallAttrs(declared []Call, index int, received Call) map[string]string {
	injected, unverified := Screen(declared, received)
	return map[string]string{
		AttrInjectedCall:       BoolStr(injected),
		AttrToolArgsUnverified: BoolStr(unverified),
		AttrSequenceAnomaly:    BoolStr(ScreenSequence(declared, index, received)),
	}
}

// Recorder is an append-only transparency log: one JSON object per line,
// created 0600 and only ever appended to. It is the paper's third deployable
// client-side defense -- a durable record of what the client actually received,
// which a later audit can compare against the provider's own view of the same
// turn. A nil Recorder, and a Recorder with an empty path, record nothing and
// are not an error.
type Recorder struct {
	mu   sync.Mutex
	path string
}

// NewRecorder returns a Recorder writing to path.
func NewRecorder(path string) *Recorder { return &Recorder{path: strings.TrimSpace(path)} }

// Path returns the file the Recorder appends to.
func (r *Recorder) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

// Record appends one entry. Attributes are sorted by encoding/json's map
// handling, so the same event always serialises the same way.
func (r *Recorder) Record(kind string, attrs map[string]string) error {
	if r == nil || r.path == "" {
		return nil
	}
	entry := struct {
		Time       string            `json:"time"`
		Kind       string            `json:"kind"`
		Attributes map[string]string `json:"attributes"`
	}{
		Time:       time.Now().UTC().Format(time.RFC3339),
		Kind:       kind,
		Attributes: attrs,
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

// BoolStr renders a bool the way every Raid attribute is rendered.
func BoolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Defaults returns the integrity attributes every adapter can stamp without
// computing anything: all false, so a policy can match the keys without a
// has() guard and behaves identically whether or not the caller emits them.
func Defaults() map[string]string {
	attrs := make(map[string]string, len(AttributeNames))
	for _, name := range AttributeNames {
		attrs[name] = "false"
	}
	return attrs
}
