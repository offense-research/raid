// Raw policy bundle schema as decoded from YAML.
//
// These structs are the strict YAML decode surface: fields are exported and
// keyed by their wire names; the loader rejects unknown keys (KnownFields).
package policy

// ApiVersion is the supported bundle schema version.
const ApiVersion = "offense.dev/raid/v1alpha1"

// Kind is the accepted bundle kind.
const Kind = "PolicyBundle"

// AllowScopes is the closed set of approval scopes.
//
//   - exact_request: the receipt is bound to the exact request hash; a
//     retry of a *different* request is rejected (default, strongest).
//   - operation:     an approval also covers subsequent requests by the same
//     principal+agent for the same operation+environment until it expires.
//   - session:       an approval also covers subsequent requests by the same
//     principal+agent+session until it expires.
//
// Scoped approvals exist for the single-user case (see `--solo`): they reduce
// re-approval friction for repetitive low-risk operations. Grants are durable,
// time-boxed, and audited; destructive tiers should stay exact_request.
var AllowScopes = map[string]bool{
	"exact_request": true,
	"operation":     true,
	"session":       true,
}

// BundleSchema is the top-level policy document.
type BundleSchema struct {
	ApiVersion    string              `yaml:"apiVersion"`
	Kind          string              `yaml:"kind"`
	Metadata      *Metadata           `yaml:"metadata"`
	Defaults      *Defaults           `yaml:"defaults"`
	Rules         []*RuleSchema       `yaml:"rules"`
	SemanticGuard *SemanticGuardSchema `yaml:"semantic_guard"`
	Tests         []*TestSchema       `yaml:"tests"`
}

// Metadata identifies the bundle.
type Metadata struct {
	Name     string `yaml:"name"`
	Revision uint64 `yaml:"revision"`
}

// Defaults configures the bundle-wide fallback effect.
type Defaults struct {
	Effect string `yaml:"effect"`
}

// RuleSchema is one policy rule.
type RuleSchema struct {
	ID          string          `yaml:"id"`
	Description string          `yaml:"description"`
	Match       *MatchSchema    `yaml:"match"`
	When        string          `yaml:"when"`
	Effect      string          `yaml:"effect"`
	Priority    int64           `yaml:"priority"`
	Approval    *ApprovalSchema `yaml:"approval"`
	SemanticGuard RuleSemantic  `yaml:"semantic_guard"`
}

// RuleSemantic scopes a semantic guard to a matched rule.
type RuleSemantic struct {
	Questions string `yaml:"questions"`
	Mode      string `yaml:"mode"`
}

// MatchSchema holds static candidate-selection fields.
type MatchSchema struct {
	Providers    []string `yaml:"providers"`
	Operations   []string `yaml:"operations"`
	Effects      []string `yaml:"effects"`
	Environments []string `yaml:"environments"`
}

// ApprovalSchema configures the approval created for this rule.
type ApprovalSchema struct {
	ApproverGroups []string `yaml:"approver_groups"`
	Quorum         uint32   `yaml:"quorum"`
	TTL            string   `yaml:"ttl"`
	AllowScope     string   `yaml:"allow_scope"`
}

// SemanticGuardSchema is the bundle-level semantic guard configuration.
type SemanticGuardSchema struct {
	Provider      string             `yaml:"provider"`
	Model         string             `yaml:"model"`
	Mode          string             `yaml:"mode"`
	DeadlineMs    int64              `yaml:"deadline"`
	FailureEffect string             `yaml:"failure_effect"`
	StateTemplate string             `yaml:"state_template"`
	Questions     string             `yaml:"questions"`
	Thresholds    map[string]float64 `yaml:"thresholds"`
	Escalation    *Escalation        `yaml:"escalation"`
}

// Escalation describes the semantic escalation effect.
type Escalation struct {
	Effect string `yaml:"effect"`
}

// TestSchema is an embedded policy test.
type TestSchema struct {
	Name   string        `yaml:"name"`
	Input  string        `yaml:"input"`
	Expect *ExpectSchema `yaml:"expect"`
}

// ExpectSchema declares the expected outcome of a test.
type ExpectSchema struct {
	Effect       string   `yaml:"effect"`
	MatchedRules []string `yaml:"matched_rules"`
}