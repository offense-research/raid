// Deterministic CBOR encoding for the canonical request hash.
//
// This is a minimal, definite-length, canonical encoder (RFC 8949 "Core
// Deterministic Encoding"): map keys are sorted by byte length then
// lexicographically, all lengths are definite, and empty maps/lists use
// definite encodings. The Raid typed Value union is encoded with length
// prefixes so that, e.g., Decimal("1.5") cannot collide with String("1.5").
package canonical

import (
	"slices"
)

// DecimalTag marks canonical.Value decimal payloads in the hash stream.
const DecimalTag = uint64(42)

// TimestampTag marks timestamp payloads.
const TimestampTag = uint64(43)

// DurationTag marks duration payloads.
const DurationTag = uint64(44)

// AppendUint appends the canonical CBOR encoding of an unsigned integer.
func AppendUint(out *[]byte, u uint64) () {
	if u < 24 {
		*out = slices.Concat(*out, []byte{byte(u)})
	} else if u < 256 {
		*out = slices.Concat(*out, []byte{0x18, byte(u)})
	} else if u < 65536 {
		*out = slices.Concat(*out, []byte{0x19, byte(u >> 8), byte(u)})
	} else if u < 4294967296 {
		*out = slices.Concat(*out, []byte{0x1a, byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
	} else {
		*out = slices.Concat(*out, []byte{0x1b,
			byte(u >> 56), byte(u >> 48), byte(u >> 40), byte(u >> 32),
			byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
	}
}

// AppendText appends a definite-length text string.
func AppendText(out *[]byte, s string) () {
	AppendHeader(out, 3, uint64(len(s)))
	*out = slices.Concat(*out, []byte(s))
}

// AppendBytes appends a definite-length byte string.
func AppendBytes(out *[]byte, b []byte) () {
	AppendHeader(out, 2, uint64(len(b)))
	*out = slices.Concat(*out, b)
}

// AppendBool appends a CBOR boolean.
func AppendBool(out *[]byte, b bool) () {
	if b {
		*out = slices.Concat(*out, []byte{0xf5})
	} else {
		*out = slices.Concat(*out, []byte{0xf4})
	}
}

// AppendNull appends CBOR null.
func AppendNull(out *[]byte) () {
	*out = slices.Concat(*out, []byte{0xf6})
}

// AppendInt appends a signed integer in canonical (non-negative) form.
func AppendInt(out *[]byte, i int64) () {
	if i >= 0 {
		AppendUint(out, uint64(i))
	} else {
		AppendHeader(out, 1, uint64(-(i + 1)))
	}
}

// AppendHeader appends a major-type header with definite length n.
func AppendHeader(out *[]byte, major uint64, n uint64) () {
	if n < 24 {
		*out = slices.Concat(*out, []byte{byte((major << 5) | n)})
		return
	}
	*out = slices.Concat(*out, []byte{byte((major << 5) | 24)})
	AppendRawUint(out, n)
}

// AppendRawUint appends the numeric argument bytes for n >= 24 headers.
func AppendRawUint(out *[]byte, n uint64) () {
	if n < 256 {
		*out = slices.Concat(*out, []byte{byte(n)})
	} else if n < 65536 {
		*out = slices.Concat(*out, []byte{byte(n >> 8), byte(n)})
	} else if n < 4294967296 {
		*out = slices.Concat(*out, []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	} else {
		*out = slices.Concat(*out, []byte{byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	}
}

// keyPair is a (key, value bytes) pair used for canonical map encoding.
type keyPair struct {
	key string
	val []byte
}

// keyPairCompare sorts by byte length then lexicographically (RFC 8949).
func keyPairCompare(a, b keyPair) int {
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

// EncodeMap appends a canonical map from string keys to pre-encoded values.
func EncodeMap(out *[]byte, pairs []keyPair) () {
	slices.SortFunc(pairs, keyPairCompare)
	AppendHeader(out, 5, uint64(len(pairs)))
	for _, p := range pairs {
		AppendText(out, p.key)
		*out = slices.Concat(*out, p.val)
	}
}

// EncodeValue appends the canonical CBOR encoding of a Raid Value.
// Objects are key-sorted; list elements keep their encoded order.
// Decimal, timestamp, and duration payloads carry distinct tags so they can
// never collide with plain strings in the hash stream.
func EncodeValue(out *[]byte, v Value) () {
	switch v.Kind() {
	case VNull:
		AppendNull(out)
	case VBool:
		AppendBool(out, v.b)
	case VInt64:
		AppendInt(out, v.i)
	case VUint64:
		AppendUint(out, v.u)
	case VString:
		AppendText(out, v.s)
	case VDecimal:
		AppendUint(out, DecimalTag)
		AppendText(out, v.s)
	case VTimestamp:
		AppendUint(out, TimestampTag)
		AppendText(out, v.s)
	case VDuration:
		AppendUint(out, DurationTag)
		AppendText(out, v.s)
	case VBytes:
		AppendBytes(out, v.bytes)
	case VList:
		AppendHeader(out, 4, uint64(len(v.arr)))
		for _, item := range v.arr {
			EncodeValue(out, item)
		}
	case VObject:
		pairs := []keyPair{}
		for k, item := range v.obj {
			var enc []byte
			EncodeValue(&enc, item)
			pairs = append(pairs, keyPair{key: k, val: enc})
		}
		EncodeMap(out, pairs)
	}
}