package api_test

import (
	"strings"
	"testing"
)

// scopedBundle grants an operation-scoped approval for shell.execute.
const scopedBundle = `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: scoped, revision: 1}
defaults: {effect: deny}
rules:
  - id: exec-needs-approval
    match:
      operations: [shell.execute]
    effect: require_approval
    approval:
      approver_groups: [maintainers]
      ttl: 5m
      allow_scope: operation
`

func execJSON(id, cmd string) string {
	return `{"schema_version":1,"request_id":"` + id + `","principal":{"subject_id":"dev","agent_id":"claude-code","session_id":"ses_1","runtime":"claude-code","groups":[],"trust_level":"local-session","revision":1},"action":{"provider":"claude-code","operation":"shell.execute","effect":"execute"},"resource":{"type":"shell","id":"/home/dev/proj","environment":"development","attributes":{"destructive":"false","exfil":"false","protected_branch":"false"}},"arguments":{"command":{"type":"string","value":"` + cmd + `"}},"context":{"source_product":"claude-code","source_request_id":"` + id + `","interactive":true}}`
}

// A scoped approval authorizes later matching requests through the API, and
// both the grant and the activity journal are observable.
func TestJournalAndGrantCoverage(t *testing.T) {
	client, _ := setupServer(t)

	// activate the scoped bundle (usr_omar is an admin approver)
	resp, err := client.Post("/v1/policies/activate", scopedBundle, "usr_omar", nil)
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"activated":true`) {
		t.Fatalf("activate failed: %v", resp.BodyString())
	}

	// first request needs approval
	resp, err = client.Post("/v1/decisions", execJSON("claude:1", "go test ./..."), "", nil)
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"effect":"require_approval"`) {
		t.Fatalf("expected require_approval: %v", resp.BodyString())
	}
	approvalID := extractID(resp.BodyString(), "approval")
	if approvalID == "" {
		t.Fatalf("missing approval id: %v", resp.BodyString())
	}

	// approve it
	resp, err = client.Post("/v1/approvals/"+approvalID+"/approve", `{"expected_version":0}`, "usr_omar", nil)
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"state":"approved"`) {
		t.Fatalf("approve failed: %v", resp.BodyString())
	}

	// a different request with the same operation+environment is now covered
	resp, err = client.Post("/v1/decisions", execJSON("claude:2", "go build ./..."), "", nil)
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"effect":"allow"`) ||
		!strings.Contains(resp.BodyString(), `"reason_code":"POLICY_GRANT_COVERED"`) {
		t.Errorf("grant should cover the second request: %v", resp.BodyString())
	}
	if !strings.Contains(resp.BodyString(), `"grant_id":"gnt_`) {
		t.Errorf("covered decision should carry a grant_id: %v", resp.BodyString())
	}

	// grants endpoint lists it
	resp, err = client.Get("/v1/grants", "")
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"operation":"shell.execute"`) {
		t.Errorf("grant not listed: %v", resp.BodyString())
	}

	// journal endpoint shows decisions, approvals, and audit events
	resp, err = client.Get("/v1/journal?limit=50", "")
	resp = mustOk(t, resp, err)
	for _, want := range []string{`"kind":"decision"`, `"kind":"approval"`, `"kind":"audit"`} {
		if !strings.Contains(resp.BodyString(), want) {
			t.Errorf("journal missing %s: %v", want, resp.BodyString())
		}
	}
}
