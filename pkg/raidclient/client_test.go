package raidclient_test

import (
	"os"
	"strings"
	"testing"

	"github.com/offense-research/raid/pkg/raidclient"
)

// TestClientGetActive exercises the client against a running daemon. The
// in-process end-to-end test (core/api/e2e_test.go) covers the full wire
// flow without an external daemon; here we pass with a note when no daemon
// is listening so the suite stays hermetic.
func TestClientGetActive(t *testing.T) {
	c := raidclient.NewClient(os.Getenv("RAID_SOCKET"))
	resp, err := c.Get("/v1/policies/active", "")
	if err != nil {
		t.Logf("no daemon reachable at %v (skipping live check): %v", c.SocketPath, err.Error())
		return
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d: %v", resp.Status, resp.BodyString())
	}
	if !strings.Contains(resp.BodyString(), `"active"`) {
		t.Errorf("unexpected body: %v", resp.BodyString())
	}
}
