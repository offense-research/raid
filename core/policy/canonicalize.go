// Deterministic canonical form of a policy bundle.
//
// The canonical Value is what gets hashed (spec 6.4 step 11-12). Omitted
// fields are absent, so adding a default-valued field to a document does not
// change the hash.
package policy

import (
	"fmt"

	"github.com/offense-research/raid/core/canonical"
)

func sVal(s string) canonical.Value { return canonical.Str(s) }
func uVal(u uint64) canonical.Value { return canonical.Uint(u) }
func iVal(i int64) canonical.Value  { return canonical.Int(i) }

func optText(m canonical.Value, key, v string) canonical.Value {
	if v == "" {
		return m
	}
	return canonical.PutObject(m, key, sVal(v))
}

func optListText(m canonical.Value, key string, v []string) canonical.Value {
	if len(v) == 0 {
		return m
	}
	l := canonical.List()
	for _, x := range v {
		l = canonical.AppendList(l, sVal(x))
	}
	return canonical.PutObject(m, key, l)
}

func optInt(m canonical.Value, key string, v int64) canonical.Value {
	if v == 0 {
		return m
	}
	return canonical.PutObject(m, key, iVal(v))
}

func optUint(m canonical.Value, key string, v uint64) canonical.Value {
	if v == 0 {
		return m
	}
	return canonical.PutObject(m, key, uVal(v))
}

func ruleToCanonical(rs *RuleSchema) canonical.Value {
	m := canonical.PutObject(canonical.Object(), "id", sVal(rs.ID))
	m = optText(m, "description", rs.Description)
	if rs.Match != nil {
		mm := canonical.Object()
		mm = optListText(mm, "providers", rs.Match.Providers)
		mm = optListText(mm, "operations", rs.Match.Operations)
		mm = optListText(mm, "effects", rs.Match.Effects)
		mm = optListText(mm, "environments", rs.Match.Environments)
		if len(mm.AsMap()) > 0 {
			m = canonical.PutObject(m, "match", mm)
		}
	}
	m = optText(m, "when", rs.When)
	m = canonical.PutObject(m, "effect", sVal(rs.Effect))
	m = optInt(m, "priority", rs.Priority)
	if rs.Approval != nil {
		am := canonical.Object()
		am = optListText(am, "approver_groups", rs.Approval.ApproverGroups)
		if rs.Approval.Quorum > 0 {
			am = canonical.PutObject(am, "quorum", uVal(uint64(rs.Approval.Quorum)))
		}
		am = optText(am, "ttl", rs.Approval.TTL)
		am = optText(am, "allow_scope", rs.Approval.AllowScope)
		m = canonical.PutObject(m, "approval", am)
	}
	return m
}

// bundleToCanonical renders the schema into its canonical Value form.
func bundleToCanonical(schema *BundleSchema) canonical.Value {
	m := canonical.Object()
	m = canonical.PutObject(m, "api_version", sVal(ApiVersion))
	m = canonical.PutObject(m, "kind", sVal(Kind))
	if schema.Metadata != nil {
		md := canonical.Object()
		md = canonical.PutObject(md, "name", sVal(schema.Metadata.Name))
		md = optUint(md, "revision", schema.Metadata.Revision)
		m = canonical.PutObject(m, "metadata", md)
	}
	if schema.Defaults != nil {
		df := canonical.Object()
		df = canonical.PutObject(df, "effect", sVal(schema.Defaults.Effect))
		m = canonical.PutObject(m, "defaults", df)
	}
	rules := canonical.List()
	for _, rs := range schema.Rules {
		rules = canonical.AppendList(rules, ruleToCanonical(rs))
	}
	m = canonical.PutObject(m, "rules", rules)
	if schema.SemanticGuard != nil {
		g := schema.SemanticGuard
		gm := canonical.Object()
		gm = optText(gm, "provider", g.Provider)
		gm = optText(gm, "model", g.Model)
		gm = optText(gm, "mode", g.Mode)
		if g.DeadlineMs > 0 {
			gm = canonical.PutObject(gm, "deadline", iVal(g.DeadlineMs))
		}
		gm = optText(gm, "failure_effect", g.FailureEffect)
		gm = optText(gm, "state_template", g.StateTemplate)
		gm = optText(gm, "questions", g.Questions)
		if len(g.Thresholds) > 0 {
			tm := canonical.Object()
			for k, v := range g.Thresholds {
				tm = canonical.PutObject(tm, k, canonical.Decimal(fmt.Sprintf("%f", v)))
			}
			gm = canonical.PutObject(gm, "thresholds", tm)
		}
		if g.Escalation != nil {
			gm = canonical.PutObject(gm, "escalation", canonical.PutObject(canonical.Object(), "effect", sVal(g.Escalation.Effect)))
		}
		m = canonical.PutObject(m, "semantic_guard", gm)
	}
	if len(schema.Tests) > 0 {
		tl := canonical.List()
		for _, ts := range schema.Tests {
			tm := canonical.Object()
			tm = optText(tm, "name", ts.Name)
			tm = canonical.PutObject(tm, "input", sVal(ts.Input))
			if ts.Expect != nil {
				em := canonical.Object()
				em = optText(em, "effect", ts.Expect.Effect)
				em = optListText(em, "matched_rules", ts.Expect.MatchedRules)
				if len(em.AsMap()) > 0 {
					tm = canonical.PutObject(tm, "expect", em)
				}
			}
			tl = canonical.AppendList(tl, tm)
		}
		m = canonical.PutObject(m, "tests", tl)
	}
	return m
}
