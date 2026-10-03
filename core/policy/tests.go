// Embedded policy test execution (activation gate).
package policy

import (
	"fmt"

	"github.com/offense-research/raid/core/canonical"
)

// runTest executes one embedded test against the freshly compiled bundle.
// The request loader maps the test input path to a decoded request; the
// expectation must match both effect and matched rule IDs.
func runTest(ts *TestSchema, b *CompiledBundle, loader func(path string) (*canonical.ActionRequest, error)) (*ExecutedTest, *CompileError) {
	name := ts.Name
	if name == "" {
		name = "(unnamed)"
	}
	if loader == nil {
		// no loader: record as skipped, not failed (library use)
		return &ExecutedTest{name: name, passed: true, detail: "skipped: no request loader"}, nil
	}
	req, rerr := loader(ts.Input)
	if rerr != nil {
		return &ExecutedTest{name: name, passed: false, detail: "cannot load input: " + rerr.Error()}, nil
	}
	res := EvaluateBundle(b, req)
	ok := true
	detail := "effect=" + res.Effect()
	if ts.Expect != nil {
		if ts.Expect.Effect != "" && ts.Expect.Effect != res.Effect() {
			ok = false
			detail = fmt.Sprintf("expected effect %s, got %s", ts.Expect.Effect, res.Effect())
		}
		if len(ts.Expect.MatchedRules) > 0 {
			expected := ts.Expect.MatchedRules
			actual := res.MatchedRuleIDs()
			if !sameIDs(expected, actual) {
				ok = false
				detail = fmt.Sprintf("expected matched_rules %v, got %v", expected, actual)
			}
		}
	}
	if res.IsError() {
		ok = false
		detail = "evaluation error: " + res.ReasonCode()
	}
	return &ExecutedTest{name: name, passed: ok, detail: detail}, nil
}

func sameIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !ContainsString(b, x) {
			return false
		}
	}
	return true
}
