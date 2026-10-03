// Static candidate-rule index.
//
// Indexes are built once at activation and are immutable. Candidate lookup
// unions the buckets the request hits plus the wildcard bucket, then applies
// full static match filtering during evaluation. Candidate order is stable:
// priority descending, then rule ID ascending (spec section 6.3).
package policy

import (
	"slices"
)

// RuleIndex maps static match fields to candidate rule indices.
type RuleIndex struct {
	rules         []*CompiledRule
	byOperation   map[string][]int64
	byProvider    map[string][]int64
	byEffect      map[string][]int64
	byEnvironment map[string][]int64
	wildcard      []int64
}

// BuildIndex constructs the immutable candidate index for compiled rules.
func BuildIndex(rules []*CompiledRule) *RuleIndex {
	var ix RuleIndex
	ix.rules = rules
	ix.byOperation = map[string][]int64{}
	ix.byProvider = map[string][]int64{}
	ix.byEffect = map[string][]int64{}
	ix.byEnvironment = map[string][]int64{}
	ix.wildcard = []int64{}
	for i, r := range rules {
		if len(r.MatchProviders()) == 0 && len(r.MatchOperations()) == 0 &&
			len(r.MatchEffects()) == 0 && len(r.MatchEnvironments()) == 0 {
			ix.wildcard = append(ix.wildcard, int64(i))
			continue
		}
		for _, v := range r.MatchOperations() {
			ix.byOperation[v] = append(ix.byOperation[v], int64(i))
		}
		for _, v := range r.MatchProviders() {
			ix.byProvider[v] = append(ix.byProvider[v], int64(i))
		}
		for _, v := range r.MatchEffects() {
			ix.byEffect[v] = append(ix.byEffect[v], int64(i))
		}
		for _, v := range r.MatchEnvironments() {
			ix.byEnvironment[v] = append(ix.byEnvironment[v], int64(i))
		}
	}
	return &ix
}

// candidateOrder sorts candidate indices by (priority desc, rule id asc).
func candidateOrder(a, b int64, rules []*CompiledRule) int {
	pa := rules[int(a)].Priority()
	pb := rules[int(b)].Priority()
	if pa != pb {
		if pa > pb {
			return -1
		}
		return 1
	}
	ia := rules[int(a)].ID()
	ib := rules[int(b)].ID()
	if ia < ib {
		return -1
	}
	if ia > ib {
		return 1
	}
	return 0
}

// ContainsString reports membership of s in lst.
func ContainsString(lst []string, s string) bool {
	for _, x := range lst {
		if x == s {
			return true
		}
	}
	return false
}

// Candidates returns candidate rule indices for a request, in stable order.
// The caller must still apply full static match filtering.
func (ix *RuleIndex) Candidates(op, provider, effectClass, environment string) []int64 {
	seen := map[int64]bool{}
	var out []int64
	// deduplicated append helper via nested loop to avoid closures
	var add func(idx int64) = func(idx int64) {
		if seen[idx] {
			return
		}
		seen[idx] = true
		out = append(out, idx)
	}
	if lst, ok := ix.byOperation[op]; ok {
		for _, idx := range lst {
			add(idx)
		}
	}
	if lst, ok := ix.byProvider[provider]; ok {
		for _, idx := range lst {
			add(idx)
		}
	}
	if lst, ok := ix.byEffect[effectClass]; ok {
		for _, idx := range lst {
			add(idx)
		}
	}
	if lst, ok := ix.byEnvironment[environment]; ok {
		for _, idx := range lst {
			add(idx)
		}
	}
	for _, idx := range ix.wildcard {
		add(idx)
	}
	// stable sort: priority desc, id asc
	slices.SortFunc(out, func(a, b int64) int { return candidateOrder(a, b, ix.rules) })
	return out
}

// MatchStatic applies the rule's static match filters to a request.
func (r *CompiledRule) MatchStatic(op, provider, effectClass, environment string) bool {
	if len(r.MatchOperations()) > 0 && !ContainsString(r.MatchOperations(), op) {
		return false
	}
	if len(r.MatchProviders()) > 0 && !ContainsString(r.MatchProviders(), provider) {
		return false
	}
	if len(r.MatchEffects()) > 0 && !ContainsString(r.MatchEffects(), effectClass) {
		return false
	}
	if len(r.MatchEnvironments()) > 0 && !ContainsString(r.MatchEnvironments(), environment) {
		return false
	}
	return true
}
