// Package crypto provides curve25519 key generation, persistence and TLS
// certificate creation for the P2P QUIC layer. Each tunelc instance
// generates one keypair on first launch and reuses it for all VPN sessions.
package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

// KeypairSize is the number of bytes in a curve25519 private or public key.
const KeypairSize = 32

// Keypair holds a static curve25519 key pair used by tunelc for the QUIC
// P2P layer.
type Keypair struct {
	Public  [KeypairSize]byte
	Private [KeypairSize]byte
}

// GenerateKeypair creates a fresh random curve25519 keypair.
func GenerateKeypair() (*Keypair, error) {
	kp := &Keypair{}
	_, err := rand.Read(kp.Private[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: random: %w", err)
	}
	// Clamp the private key as required by RFC 7748. (curve25519.ScalarBaseMult
	// does the clamping internally, but copying the standard pattern anyway).
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64

	curve25519.ScalarBaseMult(&kp.Public, &kp.Private)
	return kp, nil
}

// PublicHex returns the hex-encoded public key.
func (kp *Keypair) PublicHex() string {
	return hex.EncodeToString(kp.Public[:])
}

// PrivateHex returns the hex-encoded private key.
func (kp *Keypair) PrivateHex() string {
	return hex.EncodeToString(kp.Private[:])
}

// ParsePublicHex decodes a hex public key back into a [32]byte.
func ParsePublicHex(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("crypto: decode public hex: %w", err)
	}
	if len(b) != KeypairSize {
		return out, errors.New("crypto: wrong public key size")
	}
	copy(out[:], b)
	return out, nil
}

// ParsePrivateHex decodes a hex private key back into a [32]byte.
func ParsePrivateHex(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("crypto: decode private hex: %w", err)
	}
	if len(b) != KeypairSize {
		return out, errors.New("crypto: wrong private key size")
	}
	copy(out[:], b)
	return out, nil
}

// LoadOrGenerate reads the keypair from path (two hex lines: public then
// private). If the file does not exist, a new keypair is generated and saved.
// The file is created with 0600 permissions.
func LoadOrGenerate(path string) (*Keypair, error) {
	b, rerr := os.ReadFile(path)
	if rerr == nil {
		return parseFromLines(b)
	}
	if !errors.Is(rerr, os.ErrNotExist) {
		return nil, fmt.Errorf("crypto: read keyfile %s: %w", path, rerr)
	}
	kp, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	if err := saveToFile(path, kp); err != nil {
		return nil, fmt.Errorf("crypto: save keyfile %s: %w", path, err)
	}
	return kp, nil
}

func parseFromLines(b []byte) (*Keypair, error) {
	lines := splitLines(string(b))
	if len(lines) < 2 {
		return nil, errors.New("crypto: keyfile must have two lines (pub,priv)")
	}
	kp := &Keypair{}
	pub, err := ParsePublicHex(lines[0])
	if err != nil {
		return nil, err
	}
	priv, err := ParsePublicHex(lines[1]) // same decode size check
	if err != nil {
		return nil, err
	}
	copy(kp.Public[:], pub[:])
	copy(kp.Private[:], priv[:])
	return kp, nil
}

// saveToFile writes the public and private keys as two hex lines.
func saveToFile(path string, kp *Keypair) error {
	data := kp.PublicHex() + "\n" + kp.PrivateHex() + "\n"
	return os.WriteFile(path, []byte(data), 0o600)
}

// splitLines is a simple line-split utility.
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}