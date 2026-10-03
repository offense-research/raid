// Signed receipt claims (spec 8.7).
//
// Claims marshal to a deterministic CBOR byte stream, and that byte stream
// is what gets signed. Verification recomputes nothing: consumers verify the
// signature over the exact claims bytes and then check the exposed JSON
// fields against their expectations.
package signing

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/offense-research/raid/core/canonical"
)

// ReceiptTTL is the default lifetime of an approved-but-unconsumed receipt.
const ReceiptTTL = 60 * time.Second

// Claims is the exact receipt content bound to a single approved request.
type Claims struct {
	Version          uint32
	ReceiptID        string
	ApprovalID       string
	DecisionID       string
	RequestHash      []byte // 32 bytes
	PolicyBundleHash []byte // 32 bytes
	Effect           string
	IssuedAt         int64  // unix seconds
	ExpiresAt        int64  // unix seconds
	Nonce            []byte // 16 bytes
}

// MarshalCanonical renders the claims as deterministic CBOR bytes.
func (c *Claims) MarshalCanonical() []byte {
	var out []byte
	obj := canonical.Object()
	obj = canonical.PutObject(obj, "version", canonical.Uint(uint64(c.Version)))
	obj = canonical.PutObject(obj, "receipt_id", canonical.Str(c.ReceiptID))
	obj = canonical.PutObject(obj, "approval_id", canonical.Str(c.ApprovalID))
	obj = canonical.PutObject(obj, "decision_id", canonical.Str(c.DecisionID))
	obj = canonical.PutObject(obj, "request_hash", canonical.Bytes(c.RequestHash))
	obj = canonical.PutObject(obj, "policy_bundle_hash", canonical.Bytes(c.PolicyBundleHash))
	obj = canonical.PutObject(obj, "effect", canonical.Str(c.Effect))
	obj = canonical.PutObject(obj, "issued_at", canonical.Int(c.IssuedAt))
	obj = canonical.PutObject(obj, "expires_at", canonical.Int(c.ExpiresAt))
	obj = canonical.PutObject(obj, "nonce", canonical.Bytes(c.Nonce))
	canonical.EncodeValue(&out, obj)
	return out
}

// SignedReceipt is the signed object returned to the requesting agent.
type SignedReceipt struct {
	ClaimsBytes []byte
	Signature   []byte
	KeyID       string
}

// Sign produces a signed receipt for the claims.
func Sign(claims *Claims, key *KeyPair) *SignedReceipt {
	canonicalBytes := claims.MarshalCanonical()
	sig := key.Sign(canonicalBytes)
	return &SignedReceipt{ClaimsBytes: canonicalBytes, Signature: sig, KeyID: key.ID()}
}

// VerifyReceipt checks the signature over the exact claims bytes against the
// given issuer public key.
func VerifyReceipt(r *SignedReceipt, keyID string, pub []byte) bool {
	if r.KeyID != keyID {
		return false
	}
	pk, err := PublicKey(pub)
	if err != nil {
		return false
	}
	if !Verify(pk, r.ClaimsBytes, r.Signature) {
		return false
	}
	return true
}

// WriteReceiptJSON renders the signed receipt for consumers: the JSON
// claims, the exact signed claims bytes, the signature, and the key id.
func (r *SignedReceipt) WriteReceiptJSON(sb *strings.Builder, claims *Claims) {
	sb.WriteString(`{"claims":{`)
	sb.WriteString(`"version":`)
	sb.WriteString(strconv.FormatUint(uint64(claims.Version), 10))
	sb.WriteString(`,"receipt_id":`)
	canonical.WriteEscaped(sb, claims.ReceiptID)
	sb.WriteString(`,"approval_id":`)
	canonical.WriteEscaped(sb, claims.ApprovalID)
	sb.WriteString(`,"decision_id":`)
	canonical.WriteEscaped(sb, claims.DecisionID)
	sb.WriteString(`,"request_hash":`)
	canonical.WriteEscaped(sb, canonical.RequestHashString(claims.RequestHash))
	sb.WriteString(`,"policy_bundle_hash":`)
	canonical.WriteEscaped(sb, canonical.RequestHashString(claims.PolicyBundleHash))
	sb.WriteString(`,"effect":`)
	canonical.WriteEscaped(sb, claims.Effect)
	sb.WriteString(`,"issued_at":`)
	sb.WriteString(strconv.FormatInt(claims.IssuedAt, 10))
	sb.WriteString(`,"expires_at":`)
	sb.WriteString(strconv.FormatInt(claims.ExpiresAt, 10))
	sb.WriteString(`,"nonce":`)
	canonical.WriteEscaped(sb, hex.EncodeToString(claims.Nonce))
	sb.WriteString(`},"key_id":`)
	canonical.WriteEscaped(sb, r.KeyID)
	sb.WriteString(`,"signature":`)
	canonical.WriteEscaped(sb, hex.EncodeToString(r.Signature))
	sb.WriteString(`,"claims_bytes":`)
	canonical.WriteEscaped(sb, hex.EncodeToString(r.ClaimsBytes))
	sb.WriteByte('}')
}

// NewNonce returns a fresh 16-byte nonce.
func NewNonce() []byte {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return b[:]
}
