// Semantic result cache (spec 7.9).
//
// Optional: only successful responses from a pinned model are cached, keyed
// by the sanitized state, question set, model version, and threshold set.
// Question-set or policy changes always miss (J12); the default TTL is 60s.
package jev

import (
	"slices"

	"offense.dev/raid/core/canonical"
)

// CacheKey returns the SHA-256 key for a semantic evaluation.
func CacheKey(state, questionSet, model string, thresholdHash []byte) []byte {
	var src []byte
	src = slices.Concat(src, []byte(state))
	src = slices.Concat(src, []byte("\x00"))
	src = slices.Concat(src, []byte(questionSet))
	src = slices.Concat(src, []byte("\x00"))
	src = slices.Concat(src, []byte(model))
	src = slices.Concat(src, []byte("\x00"))
	src = slices.Concat(src, thresholdHash)
	return canonical.HashBytes(src)
}
