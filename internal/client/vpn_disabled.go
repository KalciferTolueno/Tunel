//go:build !vpn

// vpn_disabled.go provides a stub RunVPN for builds compiled WITHOUT the
// vpn build tag. Without the vpn tag, the wireguard/tun dependency and the
// platform-specific tun_*.go files are excluded; calling --vpn on such a
// binary prints a clear hint instead of failing to compile.

package client

import (
	"context"
	"errors"
)

// RunVPN is the stub. Compiled in only when -tags vpn is NOT set.
func (c *Client) RunVPN(ctx context.Context) error {
	return errors.New("VPN mode no está incluido en este binario; recompila con: go build -tags vpn -o tunelc.exe ./cmd/tunelc")
}