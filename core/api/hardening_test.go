package api_test

import (
	"strings"
	"testing"

	"github.com/offense-research/raid/core/approval"
)

// Receipt status, grant revocation, and the journal kind filter, exercised
// through the Unix-socket API.
func TestReceiptStatusGrantRevokeAndJournalFilter(t *testing.T) {
	client, _ := setupServer(t)

	resp, err := client.Post("/v1/policies/activate", scopedBundle, "usr_omar", nil)
	resp = mustOk(t, resp, err)

	resp, err = client.Post("/v1/decisions", execJSON("claude:h1", "go test ./..."), "", nil)
	resp = mustOk(t, resp, err)
	approvalID := extractID(resp.BodyString(), "approval")
	if approvalID == "" {
		t.Fatalf("missing approval id: %v", resp.BodyString())
	}

	resp, err = client.Post("/v1/approvals/"+approvalID+"/approve", `{"expected_version":0}`, "usr_omar", nil)
	resp = mustOk(t, resp, err)
	claims := approval.ClaimsFromApproveJSON(resp.BodyString())
	if claims == nil {
		t.Fatalf("no receipt claims: %v", resp.BodyString())
	}
	receiptID := claims.ReceiptID

	// GET the receipt: issued, with signed material for independent verification
	resp, err = client.Get("/v1/receipts/"+receiptID, "")
	resp = mustOk(t, resp, err)
	body := resp.BodyString()
	if !strings.Contains(body, `"status":"issued"`) {
		t.Errorf("receipt status: %v", body)
	}
	if !strings.Contains(body, `"signature":"`) || !strings.Contains(body, `"claims_bytes":"`) {
		t.Errorf("receipt missing signed material: %v", body)
	}

	// consume, then the status flips to consumed
	resp, err = client.Post("/v1/receipts/"+receiptID+"/consume", `{"consumer":"surge"}`, "", nil)
	resp = mustOk(t, resp, err)
	resp, err = client.Get("/v1/receipts/"+receiptID, "")
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"status":"consumed"`) {
		t.Errorf("receipt should be consumed: %v", resp.BodyString())
	}

	// a grant was minted by the scoped approval; revoke it
	resp, err = client.Get("/v1/grants", "")
	resp = mustOk(t, resp, err)
	grantID := firstGrantID(resp.BodyString())
	if grantID == "" {
		t.Fatalf("expected a grant: %v", resp.BodyString())
	}
	resp, err = client.Delete("/v1/grants/"+grantID, "")
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"revoked":true`) {
		t.Errorf("revoke response: %v", resp.BodyString())
	}
	resp, err = client.Get("/v1/grants", "")
	resp = mustOk(t, resp, err)
	if strings.Contains(resp.BodyString(), `"id":"gnt_`) {
		t.Errorf("grant still present after revoke: %v", resp.BodyString())
	}

	// journal filter: kind=decision returns only decision entries
	resp, err = client.Get("/v1/journal?limit=50&kind=decision", "")
	resp = mustOk(t, resp, err)
	if !strings.Contains(resp.BodyString(), `"kind":"decision"`) {
		t.Errorf("journal kind=decision returned no decisions: %v", resp.BodyString())
	}
	if strings.Contains(resp.BodyString(), `"kind":"approval"`) || strings.Contains(resp.BodyString(), `"kind":"audit"`) {
		t.Errorf("journal kind=decision leaked other kinds: %v", resp.BodyString())
	}
	// invalid kind is rejected
	resp, err = client.Get("/v1/journal?kind=bogus", "")
	if err != nil {
		t.Fatalf("journal bogus kind: %v", err)
	}
	if resp.Status != 400 {
		t.Errorf("bogus kind: got %d want 400", resp.Status)
	}
}

func firstGrantID(body string) string {
	const marker = `"id":"gnt_`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(`"id":"`):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
