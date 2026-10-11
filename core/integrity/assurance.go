package integrity

// Agent-assurance verifiers: the four classes of agent-security attack the
// per-action integrity contract above cannot see on its own.
//
//   - Trajectory (arXiv:2608.01558): per-action checks cannot catch incremental
//     state corruption, because every single action is benign in isolation while
//     the cumulative trajectory breaks the session's invariants.
//   - Tool schema / signature attestation (arXiv:2604.08407, arXiv:2606.10749):
//     bind the tool definitions the provider presents -- names, parameter
//     descriptions, schemas, and the system-prompt boundary -- so a hop cannot
//     silently edit a description, hide a tool, or tamper with the boundary.
//   - Response-delta / stream auditing (arXiv:2604.08407): screen the completion
//     as it arrives and again before it is used, against an anchored prefix, a
//     declared stop, and a digest that must not change in flight.
//   - Confinement (arXiv:2608.10530): a sub-invocation inherits its parent's
//     scope -- paths, hosts, env vars -- and may only narrow it, so a tool
//     hijack or sandbox escape is visible as an action outside the scope.
//
// Exactly like the rest of this package these verifiers decide nothing. They
// emit conclusions as resource.attributes strings; the policy bundle decides
// deterministically and fails closed. Every attribute is guarded in policy with
// has(), so an adapter that never emits them is unaffected.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
)

// Attribute names for the four agent-assurance classes. Every adapter that
// computes them emits all of them, defaulting to "false".
const (
	AttrTrajectoryTracked       = "trajectory_tracked"
	AttrTrajectoryAttested      = "trajectory_attested"
	AttrTrajectoryDrift         = "trajectory_drift"
	AttrTrajectoryUnplanned     = "trajectory_unplanned"
	AttrTrajectoryQuotaExceeded = "trajectory_quota_exceeded"

	AttrToolSchemaAttested = "tool_schema_attested"
	AttrToolSchemaMutated  = "tool_schema_mutated"
	AttrHiddenToolInjected = "hidden_tool_injected"
	AttrBoundaryTampered   = "boundary_tampered"

	AttrStreamAudited        = "stream_audited"
	AttrStreamPrefixMismatch = "stream_prefix_mismatch"
	AttrStreamSuffixInjected = "stream_suffix_injected"
	AttrResponseDelta        = "response_delta"

	AttrConfinementTracked = "confinement_tracked"
	AttrConfined           = "confined"
	AttrConfinementEscape  = "confinement_escape"
	AttrConfinementWidened = "confinement_widened"
	AttrEnvEscape          = "env_escape"
)

// AssuranceAttributeNames lists every attribute the four verifiers emit.
var AssuranceAttributeNames = []string{
	AttrTrajectoryTracked,
	AttrTrajectoryAttested,
	AttrTrajectoryDrift,
	AttrTrajectoryUnplanned,
	AttrTrajectoryQuotaExceeded,
	AttrToolSchemaAttested,
	AttrToolSchemaMutated,
	AttrHiddenToolInjected,
	AttrBoundaryTampered,
	AttrStreamAudited,
	AttrStreamPrefixMismatch,
	AttrStreamSuffixInjected,
	AttrResponseDelta,
	AttrConfinementTracked,
	AttrConfined,
	AttrConfinementEscape,
	AttrConfinementWidened,
	AttrEnvEscape,
}

func init() { AttributeNames = append(AttributeNames, AssuranceAttributeNames...) }

// ---- V1: trajectory assurance and drift -----------------------------------

// TrajectoryPlan is the declared shape of a session: the operations it expects
// to take, the ceilings it must stay under, and optionally the digest of each
// declared step in order. A plan with no fields set declares nothing, and the
// ledger then makes no claim rather than inventing one.
type TrajectoryPlan struct {
	// Operations are the declared operation slugs. Empty means any operation is
	// in plan; an operation outside a non-empty set is unplanned.
	Operations []string
	// MaxActions is the ceiling on the number of steps before the trajectory is
	// over its declared quota. Zero means no ceiling.
	MaxActions int
	// MaxTargets is the ceiling on distinct resource targets. Zero means none.
	MaxTargets int
	// Digests are the declared per-step call digests, in order. When set, a step
	// whose digest differs from the declared one -- or an extra step past the
	// declared chain -- is drift: the cumulative state was corrupted even though
	// each action looked benign.
	Digests []string
}

// Declared reports whether the plan declares anything at all.
func (p TrajectoryPlan) Declared() bool {
	return len(p.Operations) > 0 || p.MaxActions > 0 || p.MaxTargets > 0 || len(p.Digests) > 0
}

// TrajectoryStep is one step of the session as the adapter observed it.
type TrajectoryStep struct {
	Operation string
	Target    string
	Digest    string
}

// TrajectoryLedger accumulates the session's observed steps against a declared
// plan and reports cumulative drift. Record the step about to run first, then
// read Attributes: drift is a property of the trajectory including this call.
type TrajectoryLedger struct {
	mu       sync.Mutex
	plan     TrajectoryPlan
	declared bool
	steps    []TrajectoryStep
	targets  map[string]bool
}

// NewTrajectoryLedger returns a ledger tracking the given plan.
func NewTrajectoryLedger(plan TrajectoryPlan) *TrajectoryLedger {
	return &TrajectoryLedger{plan: plan, declared: plan.Declared(), targets: map[string]bool{}}
}

// Observe records one step. A nil ledger records nothing.
func (l *TrajectoryLedger) Observe(step TrajectoryStep) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.steps = append(l.steps, step)
	if step.Target != "" {
		l.targets[step.Target] = true
	}
}

// Attributes reports the trajectory's conclusions.
func (l *TrajectoryLedger) Attributes() map[string]string {
	attrs := map[string]string{
		AttrTrajectoryTracked:       "false",
		AttrTrajectoryAttested:      "false",
		AttrTrajectoryDrift:         "false",
		AttrTrajectoryUnplanned:     "false",
		AttrTrajectoryQuotaExceeded: "false",
	}
	if l == nil || !l.declared {
		// Nothing declared: make no claim, so the policy's has() guard holds and
		// a session with no plan is not silently treated as violating one.
		return attrs
	}
	l.mu.Lock()
	steps := append([]TrajectoryStep(nil), l.steps...)
	targets := len(l.targets)
	l.mu.Unlock()

	unplanned := false
	if len(l.plan.Operations) > 0 {
		allowed := map[string]bool{}
		for _, op := range l.plan.Operations {
			allowed[op] = true
		}
		for _, s := range steps {
			if !allowed[s.Operation] {
				unplanned = true
				break
			}
		}
	}

	quota := (l.plan.MaxActions > 0 && len(steps) > l.plan.MaxActions) ||
		(l.plan.MaxTargets > 0 && targets > l.plan.MaxTargets)

	chainDiverged := false
	if len(l.plan.Digests) > 0 {
		for i, s := range steps {
			if i >= len(l.plan.Digests) {
				// Running past the declared chain is cumulative drift.
				chainDiverged = true
				break
			}
			if s.Digest != l.plan.Digests[i] {
				chainDiverged = true
				break
			}
		}
	}

	attrs[AttrTrajectoryTracked] = "true"
	attrs[AttrTrajectoryUnplanned] = BoolStr(unplanned)
	attrs[AttrTrajectoryQuotaExceeded] = BoolStr(quota)
	attrs[AttrTrajectoryDrift] = BoolStr(chainDiverged || quota)
	attrs[AttrTrajectoryAttested] = BoolStr(!unplanned && !quota && !chainDiverged)
	return attrs
}

// ---- V2: tool schema / signature attestation -------------------------------

// ToolDefinition is a tool as the provider presented it this turn.
type ToolDefinition struct {
	Name   string
	Schema string // parameter descriptions and JSON schema, as declared
}

// SchemaManifest is the pinned set of tool definitions for a session and the
// pinned system-prompt boundary digest. A zero manifest pins nothing and makes
// no claim, so a client that has not configured a manifest keeps working.
type SchemaManifest struct {
	Tools          map[string]string // tool name -> digest of its declared schema
	BoundaryDigest string            // digest of the system-prompt boundary, "" if unpinned
}

// Pinned reports whether the manifest pins anything.
func (m *SchemaManifest) Pinned() bool {
	return m != nil && (len(m.Tools) > 0 || m.BoundaryDigest != "")
}

// NewSchemaManifest pins a set of tools and a boundary string. The boundary is
// digested as given; an empty boundary pins nothing.
func NewSchemaManifest(tools []ToolDefinition, boundary string) *SchemaManifest {
	m := &SchemaManifest{Tools: map[string]string{}}
	for _, td := range tools {
		m.Tools[strings.TrimSpace(td.Name)] = SchemaDigest(td.Name, td.Schema)
	}
	if strings.TrimSpace(boundary) != "" {
		m.BoundaryDigest = ResponseDigest(boundary)
	}
	return m
}

// Attest screens the tool set and boundary a provider presented this turn
// against the pinned manifest.
func (m *SchemaManifest) Attest(tools []ToolDefinition, boundary string) map[string]string {
	attrs := map[string]string{
		AttrToolSchemaAttested: "false",
		AttrToolSchemaMutated:  "false",
		AttrHiddenToolInjected: "false",
		AttrBoundaryTampered:   "false",
	}
	if !m.Pinned() {
		return attrs
	}
	mutated, hidden := false, false
	for _, td := range tools {
		name := strings.TrimSpace(td.Name)
		want, pinned := m.Tools[name]
		if !pinned {
			hidden = true
			continue
		}
		if SchemaDigest(name, td.Schema) != want {
			mutated = true
		}
	}
	boundaryTampered := m.BoundaryDigest != "" && ResponseDigest(boundary) != m.BoundaryDigest

	attrs[AttrToolSchemaMutated] = BoolStr(mutated)
	attrs[AttrHiddenToolInjected] = BoolStr(hidden)
	attrs[AttrBoundaryTampered] = BoolStr(boundaryTampered)
	attrs[AttrToolSchemaAttested] = BoolStr(!mutated && !hidden && !boundaryTampered)
	return attrs
}

// ---- V3: response-delta / stream auditing ----------------------------------

// StreamAudit is the client-side description of the completion it expects: an
// anchored prefix the completion must begin with, a declared stop marker after
// which nothing should follow, and optionally the digest of the parsed payload.
type StreamAudit struct {
	Anchor string // required prefix, "" if none
	Stop   string // declared stop marker, "" if none
	Expect string // digest of the parsed payload, "" if none
}

// Audit screens one completion. delivered is the raw text the transport handed
// the client; parsed is the text the client actually goes on to use. A hop that
// rewrites the payload between arrival and use shows up as delivered != parsed.
func (s StreamAudit) Audit(delivered, parsed string) map[string]string {
	body := strings.TrimLeft(delivered, " \t\r\n")
	prefixMismatch := s.Anchor != "" && !strings.HasPrefix(body, s.Anchor)

	suffixInjected := false
	if s.Stop != "" {
		if i := strings.Index(delivered, s.Stop); i >= 0 {
			if strings.TrimSpace(delivered[i+len(s.Stop):]) != "" {
				suffixInjected = true
			}
		}
	}

	delta := delivered != parsed
	if s.Expect != "" && ResponseDigest(parsed) != s.Expect {
		delta = true
	}

	return map[string]string{
		AttrStreamAudited:        "true",
		AttrStreamPrefixMismatch: BoolStr(prefixMismatch),
		AttrStreamSuffixInjected: BoolStr(suffixInjected),
		AttrResponseDelta:        BoolStr(delta),
	}
}

// ---- V4: environment and permission confinement ----------------------------

// ConfinementScope is what a session and every sub-invocation under it is
// confined to. An empty slice means that dimension is unconstrained.
type ConfinementScope struct {
	Paths   []string // allowed filesystem roots
	Hosts   []string // allowed network hosts (exact or domain suffix)
	EnvVars []string // allowed environment variable names
}

// Declared reports whether the scope constrains anything.
func (s *ConfinementScope) Declared() bool {
	return s != nil && (len(s.Paths) > 0 || len(s.Hosts) > 0 || len(s.EnvVars) > 0)
}

// ConfinementAction is the action being screened against the scope.
type ConfinementAction struct {
	Target  string   // filesystem path the action touches, if any
	Host    string   // network host the action reaches, if any
	EnvRefs []string // environment variable names the action references
}

// CheckConfinement screens an action against the parent scope. child, when
// non-nil, is the scope the sub-invocation asked to run under: a child scope
// broader than its parent's is a widening, which is never legitimate.
func CheckConfinement(parent *ConfinementScope, action ConfinementAction, child *ConfinementScope) map[string]string {
	attrs := map[string]string{
		AttrConfinementTracked: "false",
		AttrConfined:           "false",
		AttrConfinementEscape:  "false",
		AttrConfinementWidened: "false",
		AttrEnvEscape:          "false",
	}
	if !parent.Declared() {
		return attrs
	}

	escape := false
	if action.Target != "" && len(parent.Paths) > 0 {
		escape = !withinRoots(action.Target, parent.Paths)
	}
	if !escape && action.Host != "" && len(parent.Hosts) > 0 {
		escape = !HostMatches(action.Host, parent.Hosts)
	}

	envEscape := false
	if len(parent.EnvVars) > 0 {
		allowed := map[string]bool{}
		for _, v := range parent.EnvVars {
			allowed[v] = true
		}
		for _, ref := range action.EnvRefs {
			if !allowed[ref] {
				envEscape = true
				break
			}
		}
	}

	widened := child != nil && scopeWidens(parent, child)

	attrs[AttrConfinementTracked] = "true"
	attrs[AttrConfinementEscape] = BoolStr(escape)
	attrs[AttrEnvEscape] = BoolStr(envEscape)
	attrs[AttrConfinementWidened] = BoolStr(widened)
	attrs[AttrConfined] = BoolStr(!escape && !envEscape && !widened)
	return attrs
}

func withinRoots(target string, roots []string) bool {
	t := filepath.Clean(strings.TrimSpace(target))
	if t == "" {
		return false
	}
	for _, root := range roots {
		r := filepath.Clean(strings.TrimSpace(root))
		if r == "" {
			continue
		}
		if t == r || strings.HasPrefix(t, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// scopeWidens reports whether child grants anything parent does not. A
// dimension the parent leaves unconstrained cannot be widened by a child -- a
// child that adds a constraint of its own is narrowing, not widening.
func scopeWidens(parent, child *ConfinementScope) bool {
	if len(parent.Paths) > 0 {
		for _, p := range child.Paths {
			if !withinRoots(p, parent.Paths) {
				return true
			}
		}
	}
	if len(parent.Hosts) > 0 {
		for _, h := range child.Hosts {
			if !HostMatches(h, parent.Hosts) {
				return true
			}
		}
	}
	if len(parent.EnvVars) > 0 {
		allowed := map[string]bool{}
		for _, v := range parent.EnvVars {
			allowed[v] = true
		}
		for _, v := range child.EnvVars {
			if !allowed[v] {
				return true
			}
		}
	}
	return false
}

// ---- digests ---------------------------------------------------------------

// SchemaDigest fingerprints a tool definition: its name and its canonical
// schema text. Order- and whitespace-independent so a serialiser that reorders
// keys does not read as a mutation.
func SchemaDigest(name, schema string) string {
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(name)))
	h.Write([]byte{0})
	h.Write([]byte(canonicalText(schema)))
	return hex.EncodeToString(h.Sum(nil))
}

// ResponseDigest fingerprints completion text.
func ResponseDigest(text string) string {
	sum := sha256.Sum256([]byte(canonicalText(text)))
	return hex.EncodeToString(sum[:])
}

// canonicalText trims and, when the text is JSON, re-marshals it through Go's
// encoder, which sorts map keys. Key order and incidental whitespace therefore
// do not change the digest -- a serialiser that reorders keys must not read as
// a mutation.
func canonicalText(s string) string {
	t := strings.TrimSpace(s)
	if t == "" {
		return ""
	}
	if json.Valid([]byte(t)) {
		var v any
		if err := json.Unmarshal([]byte(t), &v); err == nil {
			if out, err := json.Marshal(v); err == nil {
				return string(out)
			}
		}
		var buf bytes.Buffer
		if err := json.Compact(&buf, []byte(t)); err == nil {
			return buf.String()
		}
	}
	return t
}
