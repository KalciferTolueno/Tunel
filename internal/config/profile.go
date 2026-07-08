package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// TunnelEntry is one persisted tunnel inside the tunelc profile.
type TunnelEntry struct {
	Name        string `json:"name,omitempty"`
	Proto       string `json:"proto"`        // "tcp" or "udp"
	PublicPort  int    `json:"public_port"`  // remote public port
	LocalTarget string `json:"local_target"` // host:port of the local service
}

// Profile is the persisted user configuration for tunelc. It is saved as JSON
// next to the tunelc executable (tunelc.json) so the next launch of the GUI
// comes back pre-filled.
//
// The IdentityKey / PrivateKey fields hold the hex-encoded curve25519 keypair
// used for QUIC point-to-point authentication. They are auto-generated on the
// first launch and never need manual editing.
type Profile struct {
	Server   string        `json:"server"`
	Token    string        `json:"token"`
	CACert   string        `json:"cacert"`
	Insecure bool          `json:"insecure"`
	LogLevel string        `json:"log_level"`
	Tunnels  []TunnelEntry `json:"tunnels"`

	IdentityKey string `json:"identity_key,omitempty"` // hex public key (curve25519)
	PrivateKey  string `json:"private_key,omitempty"`  // hex private key (curve25519)

	EdPubKey  string `json:"ed_pubkey,omitempty"`  // hex ed25519 public key for TLS cert signing
	EdPrivKey string `json:"ed_privkey,omitempty"` // hex ed25519 private key for TLS cert signing
}

// DefaultProfilePath returns the path to tunelc.json next to the running
// executable. If the executable path cannot be resolved it falls back to
// "./tunelc.json" in the current working directory.
func DefaultProfilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "tunelc.json"
	}
	dir := filepath.Dir(exe)
	return filepath.Join(dir, "tunelc.json")
}

// LoadProfile reads a profile JSON file. If the file does not exist, a fresh
// empty Profile is returned with no error (so first-launch UX is clean).
func LoadProfile(path string) (*Profile, error) {
	p := &Profile{LogLevel: "info", Tunnels: []TunnelEntry{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return p, fmt.Errorf("read profile %s: %w", path, err)
	}
	if len(b) == 0 {
		return p, nil
	}
	if err := json.Unmarshal(b, p); err != nil {
		return p, fmt.Errorf("parse profile %s: %w", path, err)
	}
	if p.LogLevel == "" {
		p.LogLevel = "info"
	}
	if p.Tunnels == nil {
		p.Tunnels = []TunnelEntry{}
	}
	return p, nil
}

// SaveProfile writes the profile JSON file with pretty indentation and
// restrictive permissions (0600) so the token stays private.
func SaveProfile(path string, p *Profile) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write profile %s: %w", path, err)
	}
	return nil
}