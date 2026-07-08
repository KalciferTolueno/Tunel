//go:build !vpn

// p2p_stub.go provides compile-time stubs for P2P types when the `vpn` tag
// is not active. The real implementations live in quic.go.

package client

import "log/slog"

type p2pManager struct{}

func newP2PManager(_ *slog.Logger, _ func(string) (string, bool), _ func() []string, _ func([]byte) error) *p2pManager {
	return &p2pManager{}
}
func (m *p2pManager) Start(_, _ []byte, _ string) error { return nil }
func (m *p2pManager) Stop()                             {}
func (m *p2pManager) Dial(_, _ string) error            { return nil }
func (m *p2pManager) Route(_ string, _ []byte) bool     { return false }
func (m *p2pManager) ActiveCount() int                  { return 0 }

func shortFPFromHex(_ string) string { return "" }