// End-to-end integration test: in-process daemon wired over a Unix socket,
// driven exactly like Surge would drive it (spec 1.2 demo + section 18.3).
package api_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/offense-research/raid/core/api"
	"github.com/offense-research/raid/core/approval"
	"github.com/offense-research/raid/core/authn"
	"github.com/offense-research/raid/core/canonical"
	"github.com/offense-research/raid/core/decision"
	"github.com/offense-research/raid/core/policy"
	"github.com/offense-research/raid/core/signing"
	"github.com/offense-research/raid/core/store"
	"github.com/offense-research/raid/core/stream"
	"github.com/offense-research/raid/pkg/raidclient"
)

const bundleYAML = `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: surge-default, revision: 7}
defaults: {effect: deny}
rules:
  - id: github-issue-reads
    match:
      providers: [github]
      operations: [github.issues.get]
      effects: [read]
    when: >-
      resource.environment != "production" ||
      principal.groups.exists(g, g == "engineering")
    effect: allow
  - id: production-label-write
    match:
      providers: [github]
      operations: [github.issues.add_labels]
      environments: [production]
    when: "true"
    effect: require_approval
    approval:
      approver_groups: [maintainers]
      ttl: 5m
      allow_scope: exact_request
  - id: deny-repository-deletion
    match:
      operations: [github.repository.delete]
    effect: deny
`

const readerJSON = `{"schema_version":1,"request_id":"surge:act_01J","principal":{"subject_id":"usr_imran","agent_id":"agt_claude","session_id":"ses_9821","runtime":"claude-code","groups":["engineering"],"trust_level":"local-session","revision":4},"action":{"provider":"github","operation":"github.issues.get","effect":"read"},"resource":{"type":"github.repository.issue","id":"repo:991234567:issue:184","environment":"staging","attributes":{"repository_id":"991234567"}},"arguments":{},"context":{"timestamp":"2026-09-22T20:00:00Z","source_product":"surge","source_version":"0.1.0","source_request_id":"act_01J","task_summary":"read issues","interactive":true}}`

const labelJSON = `{"schema_version":1,"request_id":"surge:act_02J","principal":{"subject_id":"usr_imran","agent_id":"agt_claude","session_id":"ses_9821","runtime":"claude-code","groups":["engineering"],"trust_level":"local-session","revision":4},"action":{"provider":"github","operation":"github.issues.add_labels","effect":"write"},"resource":{"type":"github.repository.issue","id":"repo:991234567:issue:184","environment":"production","attributes":{"repository_id":"991234567"}},"arguments":{"labels":{"type":"list","value":[{"type":"string","value":"needs-triage"}]}},"context":{"timestamp":"2026-09-22T20:00:00Z","source_product":"surge","source_version":"0.1.0","source_request_id":"act_02J","task_summary":"triage","interactive":true}}`

const delJSON = `{"schema_version":1,"request_id":"surge:act_03J","principal":{"subject_id":"usr_imran","agent_id":"agt_claude","session_id":"ses_9821","runtime":"claude-code","groups":["engineering"],"trust_level":"local-session","revision":4},"action":{"provider":"github","operation":"github.repository.delete","effect":"delete"},"resource":{"type":"repo","id":"repo:991234567","environment":"production","attributes":{}},"arguments":{},"context":{"timestamp":"2026-09-22T20:00:00Z","source_product":"surge","source_version":"0.1.0","source_request_id":"act_03J","task_summary":"delete","interactive":true}}`

var socketPath = "/tmp/raid-e2e-" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".sock"

func setupServer(t *testing.T) (*raidclient.Client, *signing.KeyPair) {
	t.Helper()
	dbPath := "/tmp/raid-e2e-" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".db"
	st, err := store.Open(store.Options{Path: dbPath, AuditMode: store.StrictAudit})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	engine := decision.NewEngine()
	key, _ := signing.GenerateKey()
	hub := stream.NewHub()
	as := authn.NewApproverStore(st)
	as.Upsert("usr_omar", "maintainers", true)
	as.Upsert("usr_omar", "admins", true)
	svc := approval.NewService(st, key, hub, true)
	srv := api.NewServer(api.Config{
		Engine: engine, Approvals: svc, Store: st, Hub: hub, Key: key,
		Approvers: as, AllowUIDs: nil, Evaluator: nil,
	})
	go func() {
		_ = srv.ServeUnix(socketPath)
	}()
	schema, lerr := policy.LoadBundle([]byte(bundleYAML), "e2e")
	if lerr != nil {
		t.Fatalf("load: %v", lerr.Error())
	}
	b, cerr := policy.CompileBundle(schema, policy.CompileOptions{})
	if cerr != nil {
		t.Fatalf("compile: %v", cerr.Error())
	}
	engine.Activate(b)
	client := raidclient.NewClient(socketPath)
	// wait for the socket to serve
	for i := 0; i < 200; i++ {
		if resp, err := client.Get("/v1/policies/active", ""); err == nil && resp.Status == 200 {
			return client, key
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("server never became ready")
	return client, key
}

// The full first-sprint flow: allow, require_approval, TUI-visible list,
// approve-once, signed receipt, verify, consume, replay rejection.
func TestEndToEndDemoFlow(t *testing.T) {
	client, _ := setupServer(t)

	// 1. safe read passes without interruption
	resp, err := client.Post("/v1/decisions", readerJSON, "", nil)
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"effect":"allow"`) {
		t.Errorf("reader must allow: %v", resp.BodyString())
	}

	// 2. production write requires approval and appears in the list
	resp, err = client.Post("/v1/decisions", labelJSON, "", nil)
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"effect":"require_approval"`) {
		t.Errorf("label write must require approval: %v", resp.BodyString())
	}
	resp, err = client.Get("/v1/approvals", "")
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), "production-label-write") {
		t.Errorf("pending approval not visible: %v", resp.BodyString())
	}

	// 3. deny path
	resp, err = client.Post("/v1/decisions", delJSON, "", nil)
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"effect":"deny"`) {
		t.Errorf("delete must deny: %v", resp.BodyString())
	}

	// 4. approve once (the TUI 'y' is the same endpoint)
	var approvalID string
	resp, err = client.Post("/v1/decisions", labelJSON, "", nil)
	resp = mustOk(t, resp, err)
	approvalID = extractID(resp.BodyString(), "approval")
	resp, err = client.Post("/v1/approvals/"+approvalID+"/approve",
		`{"expected_version":0}`, "usr_omar", nil)
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"state":"approved"`) {
		t.Errorf("approve failed: %v", resp.BodyString())
	}

	// 5. signed receipt verifies against the exposed public key
	keysResp, kerr := client.Get("/v1/keys", "")
	keysResp = mustOk(t, keysResp, kerr)
	keyID := extractKeyID(keysResp.BodyString())
	pubHex := extractPubKey(keysResp.BodyString())
	claims := approval.ClaimsFromApproveJSON(resp.BodyString())
	if claims == nil {
		t.Fatalf("missing receipt claims: %v", resp.BodyString())
	}
	cb, _ := hex.DecodeString(extractField(resp.BodyString(), "claims_bytes"))
	sigb, _ := hex.DecodeString(extractField(resp.BodyString(), "signature"))
	pubb, _ := hex.DecodeString(pubHex)
	rec := &signing.SignedReceipt{
		ClaimsBytes: cb, Signature: sigb, KeyID: keyID,
	}
	if !signing.VerifyReceipt(rec, keyID, pubb) {
		t.Errorf("receipt signature invalid against exposed public key")
	}
	if !canonical.RequestHashEquals(claims.RequestHash, canonical.HashRequest(decodeReq(t, labelJSON))) {
		t.Errorf("receipt request hash mismatch")
	}

	// 6. consume then replay must fail
	receiptID := claims.ReceiptID
	resp, err = client.Post("/v1/receipts/"+receiptID+"/consume", `{"consumer":"surge"}`, "", nil)
	resp = mustOk(t, resp, err)
	resp, err = client.Post("/v1/receipts/"+receiptID+"/consume", `{"consumer":"surge"}`, "", nil)
	if resp.Status != 409 {
		t.Errorf("receipt replay must 409, got %d %v", resp.Status, resp.BodyString())
	}

	// 7. a stale/concurrent approve loses (409)
	resp, err = client.Post("/v1/decisions", labelJSON, "", nil)
	resp = mustOk(t, resp, err)
	approvalID = extractID(resp.BodyString(), "approval")
	resp, err = client.Post("/v1/approvals/"+approvalID+"/approve", `{"expected_version":0}`, "usr_omar", nil)
	resp = mustOk(t, resp, err)
	resp, err = client.Post("/v1/approvals/"+approvalID+"/approve", `{"expected_version":0}`, "usr_omar", nil)
	if resp.Status != 409 {
		t.Errorf("second resolution must conflict, got %d", resp.Status)
	}
}

func decodeReq(t *testing.T, jsonDoc string) *canonical.ActionRequest {
	t.Helper()
	req, perr := canonical.DecodeRequest([]byte(jsonDoc))
	if perr != nil {
		t.Fatalf("req: %v", perr.Error())
	}
	return req
}

func mustOk(t *testing.T, resp *raidclient.Response, err error) *raidclient.Response {
	t.Helper()
	if err != nil {
		t.Fatalf("request: %v", err.Error())
	}
	if resp.Status >= 400 {
		t.Fatalf("unexpected status %d: %v", resp.Status, resp.BodyString())
	}
	return resp
}

func extractID(body, key string) string {
	needle := `"` + key + `":{"id":"`
	i := strings.Index(body, needle)
	if i < 0 {
		return ""
	}
	j := strings.Index(body[i+len(needle):], `"`)
	if j < 0 {
		return ""
	}
	return body[i+len(needle) : i+len(needle)+j]
}

func extractField(body, key string) string {
	needle := `"` + key + `":"`
	i := strings.Index(body, needle)
	if i < 0 {
		return ""
	}
	j := strings.Index(body[i+len(needle):], `"`)
	if j < 0 {
		return ""
	}
	return body[i+len(needle) : i+len(needle)+j]
}

func extractKeyID(body string) string {
	return extractField(body, "key_id")
}

func extractPubKey(body string) string {
	return extractField(body, "public_key")
}
