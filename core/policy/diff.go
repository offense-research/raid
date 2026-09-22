// Policy diff: describe authority changes, not text changes (spec 13.3).
//
// Static analysis is deliberately conservative. Anything that cannot be
// proven safe is reported REVIEW_REQUIRED rather than claiming equivalence.
package policy

import (
	"strings"
)

// DiffNote is one line of authority commentary.
type DiffNote struct {
	Level string // WIDENS AUTHORITY | ADDS APPROVAL | REMOVES DENY | RESTRICTS | REVIEW_REQUIRED
	Text  string
}

// DiffReport is the full authority diff.
type DiffReport struct {
	Notes []DiffNote
}

func (r *DiffReport) NotesList() []DiffNote { return r.Notes }

// String renders columnar output.
func (r *DiffReport) String() string {
	var sb strings.Builder
	for i, n := range r.Notes {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(n.Level)
		sb.WriteString("\n  ")
		sb.WriteString(n.Text)
	}
	return sb.String()
}

// DiffPolicy compares the authority surfaces of two parsed bundles.
func DiffPolicy(oldSchema, newSchema *BundleSchema) *DiffReport {
	rep := &DiffReport{}
	old := ruleMap(oldSchema)
	newRules := []*RuleSchema{}
	for _, r := range newSchema.Rules {
		oldR, exists := old[r.ID]
		if exists {
			diffRule(rep, oldR, r)
		} else {
			switch r.Effect {
			case "allow":
				rep.Notes = append(rep.Notes, DiffNote{Level: "WIDENS AUTHORITY", Text: "new rule " + r.ID + " grants " + describeRule(r)})
			case "deny", "require_approval":
				rep.Notes = append(rep.Notes, DiffNote{Level: "RESTRICTS", Text: "new rule " + r.ID + " restricts " + describeRule(r)})
			}
		}
		newRules = append(newRules, r)
	}
	// removed rules: dropped restrictions matter most
	for _, r := range oldSchema.Rules {
		found := false
		for _, nr := range newRules {
			if nr.ID == r.ID {
				found = true
				break
			}
		}
		if !found {
			if r.Effect == "deny" {
				rep.Notes = append(rep.Notes, DiffNote{Level: "REMOVES DENY", Text: r.ID + " no longer explicitly denied"})
			} else if r.Effect == "require_approval" {
				rep.Notes = append(rep.Notes, DiffNote{Level: "REMOVES APPROVAL", Text: r.ID + " no longer requires approval"})
			} else {
				rep.Notes = append(rep.Notes, DiffNote{Level: "RESTRICTS", Text: "rule " + r.ID + " removed (was allow)"})
			}
		}
	}
	if len(rep.Notes) == 0 {
		rep.Notes = append(rep.Notes, DiffNote{Level: "NO CHANGE", Text: "authority surfaces identical"})
	}
	return rep
}

func diffRule(rep *DiffReport, old, newR *RuleSchema) {
	// effect changes
	switch newR.Effect {
	case "deny":
		if old.Effect != "deny" {
			rep.Notes = append(rep.Notes, DiffNote{Level: "RESTRICTS", Text: newR.ID + " changed to deny"})
		}
	case "require_approval":
		if old.Effect != "require_approval" {
			rep.Notes = append(rep.Notes, DiffNote{Level: "ADDS APPROVAL", Text: newR.ID + " now requires approval"})
		}
	case "allow":
		if old.Effect == "deny" {
			rep.Notes = append(rep.Notes, DiffNote{Level: "WIDENS AUTHORITY", Text: newR.ID + " is no longer denied"})
		} else if old.Effect == "require_approval" {
			rep.Notes = append(rep.Notes, DiffNote{Level: "WIDENS AUTHORITY", Text: newR.ID + " no longer requires approval"})
		}
	}
	// approval config changes on a require_approval rule
	if old.Effect == newR.Effect && old.Effect == "require_approval" {
		if !approvalEqual(old.Approval, newR.Approval) {
			rep.Notes = append(rep.Notes, DiffNote{Level: "REVIEW_REQUIRED", Text: newR.ID + " approval configuration changed"})
		}
	}
	// static match widening
	if matchWidens(old.Match, newR.Match) {
		rep.Notes = append(rep.Notes, DiffNote{Level: "WIDENS AUTHORITY", Text: newR.ID + " match scope widened"})
	}
	// unknown CEL changes
	if old.When != newR.When {
		rep.Notes = append(rep.Notes, DiffNote{Level: "REVIEW_REQUIRED", Text: newR.ID + " condition changed (text differs; static proof not attempted)"})
	}
}

func matchWidens(old, newR *MatchSchema) bool {
	if old == nil {
		return newR == nil && false
	}
	if newR == nil {
		return false
	}
	// widening = some old restriction removed (any field value present before, absent now)
	if !listContains(old.Operations, newR.Operations) {
		return true
	}
	if !listContains(old.Providers, newR.Providers) {
		return true
	}
	if !listContains(old.Effects, newR.Effects) {
		return true
	}
	if !listContains(old.Environments, newR.Environments) {
		return true
	}
	return false
}

// listContains reports whether every old element exists in newR.
func listContains(old, newR []string) bool {
	for _, v := range old {
		ok := false
		for _, nv := range newR {
			if v == nv {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func approvalEqual(a, b *ApprovalSchema) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Quorum != b.Quorum || a.TTL != b.TTL || a.AllowScope != b.AllowScope {
		return false
	}
	if len(a.ApproverGroups) != len(b.ApproverGroups) {
		return false
	}
	return listContains(a.ApproverGroups, b.ApproverGroups) && listContains(b.ApproverGroups, a.ApproverGroups)
}

func ruleMap(schema *BundleSchema) map[string]*RuleSchema {
	m := map[string]*RuleSchema{}
	for _, r := range schema.Rules {
		m[r.ID] = r
	}
	return m
}

// describeRule renders a rule's authority surface for notes.
func describeRule(r *RuleSchema) string {
	var sb strings.Builder
	sb.WriteString(r.Effect)
	if r.Match != nil {
		if len(r.Match.Operations) > 0 {
			sb.WriteString(" for " + strings.Join(r.Match.Operations, ", "))
		}
		if len(r.Match.Environments) > 0 {
			sb.WriteString(" in " + strings.Join(r.Match.Environments, ", "))
		}
	}
	return sb.String()
}

