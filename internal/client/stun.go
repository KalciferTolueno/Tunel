// stun.go implements a thin STUN client for tunelc. It sends one Binding
// Request to the configured server and returns the discovered public
// UDP endpoint (reflexive address).
//
// We avoid the heavier pion/stun Client machinery and just build/send/parse
// raw STUN messages manually via the library's codec.

package client

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/stun"
)

// StunResult holds the discovered public UDP endpoint.
type StunResult struct {
	Addr net.UDPAddr
}

// StunConfig holds the STUN client parameters.
type StunConfig struct {
	ServerAddr string
	Timeout    time.Duration
}

// DefaultStunTimeout is the fallback request timeout.
const DefaultStunTimeout = 3 * time.Second

// Probe sends one STUN Binding Request and returns the XOR-MAPPED-ADDRESS
// from the response.
func Probe(cfg StunConfig) (*StunResult, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultStunTimeout
	}
	ra, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("stun resolve %q: %w", cfg.ServerAddr, err)
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("stun listen: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return nil, err
	}

	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.WriteTo(req.Raw, ra); err != nil {
		return nil, fmt.Errorf("stun send: %w", err)
	}
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("stun recv: %w", err)
	}
	msg := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
	if err := msg.Decode(); err != nil {
		return nil, fmt.Errorf("stun decode: %w", err)
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(msg); err != nil {
		return nil, fmt.Errorf("stun xormapped: %w", err)
	}
	return &StunResult{Addr: net.UDPAddr{IP: xor.IP, Port: xor.Port}}, nil
}