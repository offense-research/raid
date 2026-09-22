// Policy compilation: schema -> compiled, immutable, indexed bundle.
//
// Compilation happens at activation time, never on the decision path. Each
// rule's CEL condition is type-checked against the fixed Raid environment,
// must produce bool, and must not reference undeclared variables/functions.
package policy

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"cel.dev/cel-go/cel"
	"offense.dev/raid/core/canonical"
)

// TTL bounds in nanoseconds (spec section 8.4).
const (
	MinApprovalTTLNs   = 30_000_000_000
	MaxApprovalTTLNs   = 1_800_000_000_000
	DefaultApprovalTTLNs = 300_000_000_000
)

// CompileOptions controls bundle compilation.
type CompileOptions struct {
	// RequestLoader loads a test request by file path (relative to the
	// bundle file). When nil, embedded tests are skipped.
	RequestLoader func(path string) (*canonical.ActionRequest, error)
}

// CompileError reports a compilation failure.
type CompileError struct {
	msg string
}

func (e *CompileError) Error() string { return e.msg }

// ApprovalConfig is the normalized approval configuration of a rule.
type ApprovalConfig struct {
	approverGroups []string
	quorum         uint32
	ttlNs          int64
	allowScope     string
}

func (a *ApprovalConfig) ApproverGroups() []string { return a.approverGroups }
func (a *ApprovalConfig) Quorum() uint32           { return a.quorum }
func (a *ApprovalConfig) TTLNs() int64             { return a.ttlNs }
func (a *ApprovalConfig) AllowScope() string       { return a.allowScope }

// CompiledRule is one immutable, compiled rule.
type CompiledRule struct {
	id          string
	description string
	effect      string
	priority    int64
	whenText    string
	program     cel.Program
	always      bool
	approval    *ApprovalConfig
	mProviders  []string
	mOperations []string
	mEffects    []string
	mEnvironments []string
}

func (r *CompiledRule) ID() string                 { return r.id }
func (r *CompiledRule) Description() string        { return r.description }
func (r *CompiledRule) Effect() string             { return r.effect }
func (r *CompiledRule) Priority() int64            { return r.priority }
func (r *CompiledRule) WhenText() string           { return r.whenText }
func (r *CompiledRule) PassAlways() bool           { return r.always }
func (r *CompiledRule) Approval() *ApprovalConfig  { return r.approval }
func (r *CompiledRule) MatchProviders() []string   { return r.mProviders }
func (r *CompiledRule) MatchOperations() []string  { return r.mOperations }
func (r *CompiledRule) MatchEffects() []string     { return r.mEffects }
func (r *CompiledRule) MatchEnvironments() []string { return r.mEnvironments }

// NewStaticRule builds an always-true rule with only static match fields.
// It exists for index construction and benchmarks (P08) without paying CEL
// compile cost.
func NewStaticRule(id string, ops []string) *CompiledRule {
	return &CompiledRule{
		id: id, effect: "allow", always: true,
		mOperations: ops,
	}
}
// A rule without a `when` always matches. CEL runtime errors are surfaced
// (they are policy errors, never false).
func (r *CompiledRule) EvaluateWhen(activation map[string]any) (bool, error) {
	if r.always {
		return true, nil
	}
	out, _, err := r.program.Eval(activation)
	if err != nil {
		return false, err
	}
	native, cerr := out.ConvertToNative(reflect.TypeFor[bool]())
	if cerr != nil {
		return false, cerr
	}
	b, ok := native.(bool)
	if !ok {
		return false, errors.New("raid: CEL condition did not produce a boolean at runtime")
	}
	return b, nil
}

// CompiledBundle is the immutable activated bundle.
type CompiledBundle struct {
	id           string
	name         string
	revision     uint64
	defaultEffect string
	hash         []byte
	canonical    canonical.Value
	rules        []*CompiledRule
	index        *RuleIndex
	guard        *CompiledGuard
	tests        []*ExecutedTest
}

func (b *CompiledBundle) ID() string               { return b.id }
func (b *CompiledBundle) Name() string             { return b.name }
func (b *CompiledBundle) Revision() uint64         { return b.revision }
func (b *CompiledBundle) DefaultEffect() string    { return b.defaultEffect }
func (b *CompiledBundle) Hash() []byte             { return b.hash }
func (b *CompiledBundle) Canonical() canonical.Value { return b.canonical }
func (b *CompiledBundle) Rules() []*CompiledRule   { return b.rules }
func (b *CompiledBundle) Index() *RuleIndex        { return b.index }
func (b *CompiledBundle) Guard() *CompiledGuard    { return b.guard }
func (b *CompiledBundle) Tests() []*ExecutedTest   { return b.tests }

// CompiledGuard is the normalized semantic guard configuration.
type CompiledGuard struct {
	provider      string
	model         string
	mode          string
	deadlineMs    int64
	failureEffect string
	stateTemplate string
	questions     string
	thresholds    map[string]float64
	escalation    string
}

func (g *CompiledGuard) Provider() string                 { return g.provider }
func (g *CompiledGuard) Model() string                    { return g.model }
func (g *CompiledGuard) Mode() string                     { return g.mode }
func (g *CompiledGuard) DeadlineMs() int64                { return g.deadlineMs }
func (g *CompiledGuard) FailureEffect() string            { return g.failureEffect }
func (g *CompiledGuard) StateTemplate() string            { return g.stateTemplate }
func (g *CompiledGuard) Questions() string                { return g.questions }
func (g *CompiledGuard) Thresholds() map[string]float64   { return g.thresholds }
func (g *CompiledGuard) Escalation() string               { return g.escalation }

// NewGuardForTest builds a compiled guard for tests and the semantic flow.
func NewGuardForTest(mode, failureEffect, escalation string, thresholds map[string]float64) *CompiledGuard {
	return &CompiledGuard{
		provider: "typesafe", model: "jev-1.13.0", mode: mode,
		deadlineMs: 500, failureEffect: failureEffect,
		stateTemplate: "action-risk-v1", questions: "agent-action-risk-v1",
		thresholds: thresholds, escalation: escalation,
	}
}

// DefaultApprovalConfig returns the fail-safe approval configuration used
// when Jev escalates an allow to require_approval without a policy rule.
func DefaultApprovalConfig() *ApprovalConfig {
	return &ApprovalConfig{
		approverGroups: nil, quorum: 1, ttlNs: DefaultApprovalTTLNs,
		allowScope: "exact_request",
	}
}

// ExecutedTest records an embedded-test outcome at activation.
type ExecutedTest struct {
	name   string
	passed bool
	detail string
}

func (t *ExecutedTest) Name() string   { return t.name }
func (t *ExecutedTest) Passed() bool   { return t.passed }
func (t *ExecutedTest) Detail() string { return t.detail }

// CompileBundle compiles a strict-decoded schema into an immutable bundle.
func CompileBundle(schema *BundleSchema, opts CompileOptions) (*CompiledBundle, *CompileError) {
	if schema == nil {
		return nil, &CompileError{msg: "nil bundle"}
	}
	// duplicate rule id rejection
	seen := map[string]bool{}
	for _, rs := range schema.Rules {
		if seen[rs.ID] {
			return nil, &CompileError{msg: "duplicate rule id " + rs.ID}
		}
		seen[rs.ID] = true
		if rs.Effect != "allow" && rs.Effect != "deny" && rs.Effect != "require_approval" {
			return nil, &CompileError{msg: "rule " + rs.ID + " has invalid effect " + rs.Effect}
		}
		if rs.Effect == "require_approval" && rs.Approval == nil {
			return nil, &CompileError{msg: "rule " + rs.ID + " requires an approval block"}
		}
	}
	// shared CEL environment: fixed Raid variables only
	env, err := cel.NewEnv(
		cel.Variable("principal", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("action", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("arguments", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("context", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, &CompileError{msg: "failed to construct CEL environment: " + err.Error()}
	}
	var rules []*CompiledRule
	for _, rs := range schema.Rules {
		cr, cerr := compileRule(env, rs)
		if cerr != nil {
			return nil, cerr
		}
		rules = append(rules, cr)
	}
	b := &CompiledBundle{
		id:            schema.Metadata.Name + ":" + itoa(schema.Metadata.Revision),
		name:          schema.Metadata.Name,
		revision:      schema.Metadata.Revision,
		defaultEffect: schema.Defaults.Effect,
		rules:         rules,
	}
	b.index = BuildIndex(rules)
	// canonical form + hash
	b.canonical = bundleToCanonical(schema)
	b.hash = canonical.HashCanonical(b.canonical)
	// semantic guard
	if schema.SemanticGuard != nil {
		g, gerr := compileGuard(schema.SemanticGuard)
		if gerr != nil {
			return nil, gerr
		}
		b.guard = g
	}
	// embedded tests: must pass before the bundle may activate
	var tests []*ExecutedTest
	for _, ts := range schema.Tests {
		et, terr := runTest(ts, b, opts.RequestLoader)
		if terr != nil {
			return nil, terr
		}
		tests = append(tests, et)
		if !et.passed {
			return nil, &CompileError{msg: "embedded test failed: " + et.name + ": " + et.detail}
		}
	}
	b.tests = tests
	return b, nil
}

func compileRule(env *cel.Env, rs *RuleSchema) (*CompiledRule, *CompileError) {
	var cr CompiledRule
	cr.id = rs.ID
	cr.description = rs.Description
	cr.effect = rs.Effect
	cr.priority = rs.Priority
	cr.whenText = rs.When
	if rs.Match != nil {
		cr.mProviders = rs.Match.Providers
		cr.mOperations = rs.Match.Operations
		cr.mEffects = rs.Match.Effects
		cr.mEnvironments = rs.Match.Environments
	}
	if rs.When == "" {
		cr.always = true
	} else {
		ast, issues := env.Compile(rs.When)
		if err := issues.Err(); err != nil {
			return nil, &CompileError{msg: "rule " + rs.ID + ": CEL check failed: " + err.Error()}
		}
		if ast.OutputType().TypeName() != "bool" {
			return nil, &CompileError{msg: "rule " + rs.ID + ": when expression must evaluate to bool, got " + ast.OutputType().TypeName()}
		}
		prg, perr := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		if perr != nil {
			return nil, &CompileError{msg: "rule " + rs.ID + ": CEL program construction failed: " + perr.Error()}
		}
		cr.program = prg
	}
	if rs.Approval != nil {
		ttlNs, terr := parseTTL(rs.Approval.TTL)
		if terr != "" {
			return nil, &CompileError{msg: "rule " + rs.ID + ": " + terr}
		}
		if !AllowScopes[rs.Approval.AllowScope] {
			return nil, &CompileError{msg: "rule " + rs.ID + ": unsupported approval allow_scope " + rs.Approval.AllowScope}
		}
		if rs.Approval.Quorum == 0 {
			rs.Approval.Quorum = 1
		}
		cr.approval = &ApprovalConfig{
			approverGroups: rs.Approval.ApproverGroups,
			quorum:         rs.Approval.Quorum,
			ttlNs:          ttlNs,
			allowScope:     rs.Approval.AllowScope,
		}
	}
	return &cr, nil
}

// parseTTL parses a duration string and applies the MVP bounds.
func parseTTL(s string) (int64, string) {
	if s == "" {
		return DefaultApprovalTTLNs, ""
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Sprintf("invalid approval ttl %q", s)
	}
	ns := d.Nanoseconds()
	if ns < MinApprovalTTLNs {
		return 0, "approval ttl below minimum (30s)"
	}
	if ns > MaxApprovalTTLNs {
		return 0, "approval ttl above maximum (30m)"
	}
	return ns, ""
}

func compileGuard(g *SemanticGuardSchema) (*CompiledGuard, *CompileError) {
	if g.Provider != "typesafe" {
		return nil, &CompileError{msg: "unsupported semantic_guard provider " + g.Provider}
	}
	mode := g.Mode
	if mode == "" {
		mode = "off"
	}
	if mode != "off" && mode != "shadow" && mode != "enforce" {
		return nil, &CompileError{msg: "invalid semantic_guard.mode " + mode}
	}
	if mode == "enforce" {
		if g.Model == "" || g.Model == "jev-latest" {
			return nil, &CompileError{msg: "enforcement requires a pinned model version"}
		}
	}
	failure := g.FailureEffect
	if failure == "" {
		failure = "require_approval"
	}
	if failure != "require_approval" && failure != "deny" {
		return nil, &CompileError{msg: "invalid semantic_guard.failure_effect " + failure}
	}
	escalation := "require_approval"
	if g.Escalation != nil && g.Escalation.Effect != "" {
		escalation = g.Escalation.Effect
	}
	if escalation != "require_approval" && escalation != "deny" {
		return nil, &CompileError{msg: "invalid semantic escalation effect " + escalation}
	}
	deadline := g.DeadlineMs
	if deadline <= 0 {
		deadline = 500
	}
	return &CompiledGuard{
		provider: g.Provider, model: g.Model, mode: mode,
		deadlineMs: deadline, failureEffect: failure,
		stateTemplate: g.StateTemplate, questions: g.Questions,
		thresholds: g.Thresholds, escalation: escalation,
	}, nil
}

func itoa(u uint64) string {
	return fmt.Sprintf("%d", u)
}