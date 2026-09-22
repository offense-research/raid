package raidclient_test

import (
	"fmt"
	"testing"

	"offense.dev/raid/pkg/raidclient"
)

func TestClientGetActive(t *testing.T) {
	c := raidclient.NewClient("/tmp/raiddemo/raid.sock")
	resp, err := c.Get("/v1/policies/active", "")
	if err != nil {
		t.Fatalf("get: %v", err.Error())
	}
	fmt.Printf("status=%d body=%v\n", resp.Status, resp.BodyString())
	if resp.Status != 200 {
		t.Errorf("expected 200, got %d", resp.Status)
	}
}