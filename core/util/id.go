// Small shared helpers: prefixed random identifiers.
package util

import (
	"crypto/rand"
	"encoding/hex"
)

// NewID returns a prefix_<20 hex chars> identifier suitable for decisions,
// approvals, and receipts. 80 bits of randomness is ample for the MVP
// single-node deployment; collisions are astronomically unlikely.
func NewID(prefix string) string {
	var b [10]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}
