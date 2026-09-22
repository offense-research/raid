// Canonical request hashing.
//
// HashRequest binds exactly the policy-relevant identity of a request:
// schema version, principal (subject, agent, session, trust level,
// revision), provider and operation, resource (type, id, environment,
// sorted attributes), typed normalized arguments (sorted keys), source
// product, source request ID, and policy-relevant context fields.
//
// Timestamps are excluded unless the policy references them; the MVP
// includes the context fields a policy may legally reference (interactive
// and task_summary) and always excludes context.timestamp.
package canonical

import (
	"encoding/hex"
	"slices"

	"crypto/sha256"
)

// HashSize is the request-hash byte length (SHA-256).
const HashSize = 32


// Content kinds provide drift protection for the hash stream.
const (
	HKRequest   = uint64(1)
	HKPrincipal = uint64(2)
	HKAction    = uint64(3)
	HKResource  = uint64(4)
	HKArguments = uint64(5)
	HKContext   = uint64(6)
)

// HashRequest computes SHA-256 over the deterministic CBOR stream binding
// the request. Requests that differ in any bound field produce a different
// hash; identical normalized requests always produce the same hash.
// HashRequest computes the canonical request hash for a normalized request.
func HashRequest(r *ActionRequest) []byte {
	var out []byte
	AppendUint(&out, HKRequest)
	AppendInt(&out, int64(r.schemaVersion))

	// principal: subject, agent, session, trust level, revision
	// (groups intentionally excluded per spec section 5.3)
	AppendUint(&out, HKPrincipal)
	var po []byte
	AppendText(&po, r.principal.subjectID)
	AppendText(&po, r.principal.agentID)
	AppendText(&po, r.principal.sessionID)
	AppendText(&po, r.principal.trustLevel)
	AppendUint(&po, r.principal.revision)
	out = ConcatBytes(out, po)

	// action
	AppendUint(&out, HKAction)
	var ao []byte
	AppendText(&ao, r.action.provider)
	AppendText(&ao, r.action.operation)
	out = ConcatBytes(out, ao)

	// resource: type, id, environment, sorted attributes
	AppendUint(&out, HKResource)
	var ro []byte
	AppendText(&ro, r.resource.typ)
	AppendText(&ro, r.resource.id)
	AppendText(&ro, r.resource.environment)
	attrs := sortedStringMap(r.resource.attributes)
	for _, kv := range attrs {
		AppendText(&ro, kv.key)
		AppendText(&ro, kv.val)
	}
	out = ConcatBytes(out, ro)

	// typed normalized arguments, key-sorted
	AppendUint(&out, HKArguments)
	var ar []byte
	argPairs := []sortedPair{}
	for k, v := range r.arguments {
		var enc []byte
		EncodeValue(&enc, v)
		argPairs = append(argPairs, sortedPair{key: k, val: enc})
	}
	slices.SortFunc(argPairs, sortedPairCompare)
	AppendHeader(&ar, 4, uint64(len(argPairs)))
	for _, kv := range argPairs {
		AppendText(&ar, kv.key)
		ar = ConcatBytes(ar, kv.val)
	}
	out = ConcatBytes(out, ar)

	// context: source product, source request id, interactive, task summary
	AppendUint(&out, HKContext)
	var co []byte
	AppendText(&co, r.context.sourceProduct)
	AppendText(&co, r.context.sourceRequestID)
	AppendBool(&co, r.context.interactive)
	AppendText(&co, r.context.taskSummary)
	out = ConcatBytes(out, co)

	sum := sha256.Sum256(out)
	return sum[:]
}

// HashBytes returns the SHA-256 digest of arbitrary bytes.
func HashBytes(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// HashCanonical returns the SHA-256 digest of a canonical Value encoding.
func HashCanonical(v Value) []byte {
	var enc []byte
	EncodeValue(&enc, v)
	sum := sha256.Sum256(enc)
	return sum[:]
}

// RequestHashString renders a digest as "sha256:<hex>".
func RequestHashString(h []byte) string {
	return "sha256:" + hex.EncodeToString(h)
}

// RequestHashEquals compares digests without early-exit branching.
func RequestHashEquals(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte = 0
	for i := 0; i < len(a); i++ {
		d = d | (a[i] ^ b[i])
	}
	return d == 0
}

// ConcatBytes is a short alias for byte-slice concatenation.
func ConcatBytes(a, b []byte) []byte { return slices.Concat(a, b) }



// sortedPair mirrors the CBOR key sorting requirement for arguments.
type sortedPair struct {
	key string
	val []byte
}

func sortedPairCompare(a, b sortedPair) int {
	if len(a.key) != len(b.key) {
		if len(a.key) < len(b.key) {
			return -1
		}
		return 1
	}
	if a.key < b.key {
		return -1
	}
	if a.key > b.key {
		return 1
	}
	return 0
}

type nameValue struct {
	key string
	val string
}

func nameValueCompare(a, b nameValue) int {
	if len(a.key) != len(b.key) {
		if len(a.key) < len(b.key) {
			return -1
		}
		return 1
	}
	if a.key < b.key {
		return -1
	}
	if a.key > b.key {
		return 1
	}
	return 0
}

// sortedStringMap returns attributes as length-ordered, lexicographic pairs.
func sortedStringMap(m map[string]string) []nameValue {
	pairs := []nameValue{}
	for k, v := range m {
		pairs = append(pairs, nameValue{key: k, val: v})
	}
	slices.SortFunc(pairs, nameValueCompare)
	return pairs
}