// Ed25519 key management for receipt signing (spec 14.3).
//
// The private key is kept in memory only for the MVP daemon process; the
// key-seed file on disk is the durable secret (rotations and on-disk
// encryption are cloud/hosted features).
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// KeyPair wraps an Ed25519 key pair.
type KeyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   string // short key identifier (first 8 bytes of pub key hash)
}

// GenerateKey creates a fresh Ed25519 key pair.
func GenerateKey() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{pub: pub, priv: priv, id: keyID(pub)}, nil
}

// FromSeed reconstructs a key pair from a 32-byte seed (for persistence).
func FromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("raid: ed25519 seed must be 32 bytes")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{pub: pub, priv: priv, id: keyID(pub)}, nil
}

func keyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// ID returns the key identifier used in receipts.
func (k *KeyPair) ID() string { return k.id }

// Public returns the raw public key bytes.
func (k *KeyPair) Public() []byte { return []byte(k.pub) }

// Seed returns the 32-byte seed for persistence.
func (k *KeyPair) Seed() []byte { return k.priv.Seed() }

// Sign signs a canonical message.
func (k *KeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(k.priv, message)
}

// PublicKey decodes a raw public key for verification.
func PublicKey(pub []byte) (ed25519.PublicKey, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("raid: invalid ed25519 public key")
	}
	return ed25519.PublicKey(pub), nil
}

// Verify checks a signature against a raw public key.
func Verify(pub ed25519.PublicKey, message, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, message, sig)
}
