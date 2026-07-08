// Package server implements tunels, the public-side of the reverse tunnel.
//
// Listening flow:
//  1. Accept TLS connections on the control bind address.
//  2. For each connection, create a yamux.Server session that owns all
//     tunnels multiplexed over it (a Connection).
//  3. The Connection accepts control streams: each one carries a single Auth
//     frame that requests one tunnel (a public listener + a local target on
//     the connected client). One yamux session = many tunnels.
//  4. For each granted tunnel, the Connection opens data streams on demand
//     (one per inbound public TCP conn for TCP tunnels, or one per inbound
//     public peer for UDP tunnels). Every data stream starts with a 2-byte
//     tunnel ID header so the client can demux.
//
// UDP tunnels carry length-prefixed datagram frames after the tunnel ID
// header; see internal/protocol/framing.go for the byte format.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"tunel/internal/config"
)

// Server is the public-side tunel server.
type Server struct {
	logger      *slog.Logger
	cfg         Config
	tlsListener net.Listener
	vpnHub      *vpnHub
}

// Config holds the server runtime configuration.
type Config struct {
	Bind         string
	Token        string
	CertFile     string
	KeyFile      string
	AllowedPorts map[int]struct{}
	// VPNEnabled, when true, makes the server accept Auth{proto:"vpn"} frames
	// and run a Layer-3 VPN hub that routes/broadcasts packets between peers.
	// Defaults to false (legacy TCP/UDP tunnel behavior only).
	VPNEnabled bool

	// VPNSubnet, used when VPNEnabled, is the subnet the allocator assigns
	// IPs from (default "10.99.0.0/24").
	VPNSubnet string
}

// New constructs a Server. Use Run to start accepting connections.
func New(cfg Config, logger *slog.Logger) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", cfg.Bind, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.Bind, err)
	}
	s := &Server{
		logger:      logger.With("component", "server"),
		cfg:         cfg,
		tlsListener: ln,
	}
	if cfg.VPNEnabled {
		hub, err := newVPNHub(s.logger)
		if err != nil {
			return nil, fmt.Errorf("vpn hub: %w", err)
		}
		s.vpnHub = hub
		s.logger.Info("vpn hub habilitado")
	}
	return s, nil
}

// vpnHub returns the server's VPN hub, or nil if VPN mode is disabled.
func (s *Server) vpn() *vpnHub { return s.vpnHub }

// Addr returns the control listener address. Useful for tests where Bind is
// ":0" (auto-assigned).
func (s *Server) Addr() net.Addr { return s.tlsListener.Addr() }

// Run blocks until ctx is canceled or the listener fails irrecoverably.
func (s *Server) Run(ctx context.Context) error {
	s.logger.Info("tunels listening", "bind", s.cfg.Bind)

	var wg sync.WaitGroup
	defer wg.Wait()

	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := s.tlsListener.Accept()
			if err != nil {
				errCh <- err
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.handleConnection(ctx, conn)
			}()
		}
	}()

	select {
	case <-ctx.Done():
		_ = s.tlsListener.Close()
		return nil
	case err := <-errCh:
		return err
	}
}

// handleConnection accepts a single TLS connection from a tunelc and walks
// it through the yamux + per-tunnel handshake loop. One yamux session can
// open many tunnels, each via its own control stream.
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	connLog := s.logger.With("remote", remoteAddr)
	defer conn.Close()

	ymx, err := yamux.Server(conn, yamuxCfg())
	if err != nil {
		connLog.Error("yamux server", "err", err)
		return
	}
	defer ymx.Close()

	c := newConnection(s, ymx, connLog)
	c.run(ctx)
}

// yamuxCfg returns a comfortable server-side yamux configuration tuned for
// tunnel traffic. A 30s write timeout flushes idle streams that have crashed
// peers without us noticing.
func yamuxCfg() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.ConnectionWriteTimeout = 30 * time.Second
	return cfg
}

// portAllowed reports whether port is in the server's AllowedPorts whitelist.
// An empty whitelist means any port is allowed.
func (s *Server) portAllowed(port int) bool {
	if len(s.cfg.AllowedPorts) == 0 {
		return true
	}
	_, ok := s.cfg.AllowedPorts[port]
	return ok
}

// validProto reports whether proto is a supported tunnel transport string.
// Empty is treated as "tcp" for backward compatibility with old clients.
// "vpn" is accepted only on the VPN-enabled code path; the multiplier here
// reports it as supported and lets the caller route to the VPN hub.
func validProto(proto string) (string, bool) {
	if proto == "" || proto == "tcp" {
		return "tcp", true
	}
	if proto == "udp" {
		return "udp", true
	}
	if proto == "vpn" {
		return "vpn", true
	}
	return "", false
}

// ensure config import stays referenced if New moves around.
var _ = config.ParseAllowedPorts