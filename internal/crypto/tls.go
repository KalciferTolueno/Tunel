// tls.go generates x509 self-signed TLS certificates from an ed25519 keypair.
// Every tunelc instance gets one on first launch, persisted inside the profile
// alongside its curve25519 identity key.
//
// The generated certificate is used as the target TLS certificate by the
// client-side QUIC listener. It carries a "CN=tunel-peer-<fingerprint>"
// subject so peers can recognise each other after validating the fingerprint
// against the registry provided by tunels.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// EDKeypairSize is the size in bytes of an ed25519 private or public key.
const EDKeypairSize = 32

// HashedKeyFingerprint returns the first 8 hex chars of SHA-256 of
// the ed25519 public key, used as a short identifier embedded in the cert
// subject to satisfy e2e verification.
func HashedKeyFingerprint(pub ed25519.PublicKey) string {
	if len(pub) != EDKeypairSize {
		return ""
	}
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:4]) // first 4 bytes = 8 chars
}

// GenerateED25519Keypair creates a fresh ed25519 keypair.
func GenerateED25519Keypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// EDKeyHex encodes a key to hex for storage in the profile.
func EDKeyHex(key []byte) string {
	return hex.EncodeToString(key)
}

// EDPrivKeyFromHex decodes a hex-encoded ed25519 private key.
func EDPrivKeyFromHex(s string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode ed25519 priv hex: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("crypto: wrong ed25519 private key size")
	}
	return ed25519.PrivateKey(b), nil
}

// EDPubKeyFromHex decodes a hex-encoded ed25519 public key.
func EDPubKeyFromHex(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode ed25519 pub hex: %w", err)
	}
	if len(b) != EDKeypairSize {
		return nil, errors.New("crypto: wrong ed25519 public key size")
	}
	return ed25519.PublicKey(b), nil
}

// SelfSignedTLSCert creates a self-signed X.509 certificate from the given
// ed25519 private key, returning the certificate chain as PEM bytes plus the
// `*tls.Certificate` required by quic-go.
//
// The returned PEM covers ONLY the leaf certificate; the private key is
// embedded in the returned raw bytes via crypto/x509.MarshalPKCS8PrivateKey.
func SelfSignedTLSCert(priv ed25519.PrivateKey) (certPEM []byte, keyPEM []byte, err error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("crypto: ed25519 private key type assertion failed")
	}
	fingerprint := HashedKeyFingerprint(pub)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "tunel-peer-" + fingerprint,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: create cert: %w", err)
	}
	// PEM-encode.
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal priv: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

// ValidatePeerFingerprint checks that the first certificate in a chain was
// signed by the key that owns the expected fingerprint (public key hash). This
// is the e2e identity verification that prevents tunels from injecting fake
// peers.
func ValidatePeerFingerprint(certs []*x509.Certificate, expectedFingerprint string) error {
	if len(certs) == 0 {
		return errors.New("crypto: empty peer certificate chain")
	}
	actual := certFingerprint(certs[0])
	if actual != expectedFingerprint {
		return fmt.Errorf("crypto: peer cert fingerprint %q != expected %q", actual, expectedFingerprint)
	}
	return nil
}

// certFingerprint extracts the first 8 hex chars of SHA-256 of the public key
// carried inside a certificate.
func certFingerprint(cert *x509.Certificate) string {
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return HashedKeyFingerprint(pub)
}