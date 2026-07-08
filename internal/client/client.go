// Package client implements tunelc, the local-side of the reverse tunnel.
//
// Multi-tunnel flow:
//  1. Dial the server (TLS, CA-pinned) at the control endpoint.
//  2. Wrap the connection with yamux.Client so the server can open data
//     streams back to us, and so we can open as many control streams as
//     tunnels we want to request.
//  3. For each tunnel in cfg.Tunnels open a control stream, send an Auth
//     frame, wait for AuthOK with the assigned TunnelID. Remember the
//     TunnelID -> localTarget/proto mapping.
//  4. Accept inbound yamux data streams in a loop. Each one starts with a
//     2-byte TunnelID header; look up the tunnel and dispatch:
//       - tcp: dial local, io.Copy both ways (raw bytes).
//       - udp: read a HELLO frame, open a UDP socket to the local target,
//         then forward datagrams both ways using length-prefixed frames.
//  5. Each control stream runs its own Ping keepalive loop.
//  6. On any tunnel terminating we emit events to the OnEvent observer.
//  7. Run returns when all tunnels are down OR ctx is cancelled. Outside
//     reconnection handles retry.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"tunel/internal/protocol"
)

// TunnelSpec defines a single forwarding rule requested by the client.
type TunnelSpec struct {
	Proto       string `json:"proto"`        // "tcp" or "udp"
	PublicPort  int    `json:"public_port"`  // remote public port on the VPS
	LocalTarget string `json:"local_target"` // host:port of the local service
	Name        string `json:"name,omitempty"`
}

// Client holds the configuration for a tunelc instance.
type Client struct {
	logger *slog.Logger
	cfg    Config

	// P2P peer tracking (populated by VPN signaling messages). Key is the
	// peer's VPN IP (e.g. "10.99.0.2"). Future QUIC code uses it to dial.
	p2pMu    sync.RWMutex
	p2pPeers map[string]*protocol.PeerInfo

	// p2pManager is the active QUIC P2P manager, created during VPN mode.
	// nil when not running VPN or when P2P is not available.
	p2pMgr *p2pManager
}

// storePeer inserts or updates a peer in the registry. Thread-safe.
func (c *Client) storePeer(pi protocol.PeerInfo) {
	c.p2pMu.Lock()
	if c.p2pPeers == nil {
		c.p2pPeers = make(map[string]*protocol.PeerInfo)
	}
	// Clone to avoid sharing mutable pointer with caller.
	cp := &protocol.PeerInfo{
		Pubkey:       pi.Pubkey,
		IP:           pi.IP,
		StunEndpoint: pi.StunEndpoint,
	}
	c.p2pPeers[pi.IP] = cp
	c.p2pMu.Unlock()
}

// removePeer deletes a peer from the registry. Thread-safe.
func (c *Client) removePeer(ip string) {
	c.p2pMu.Lock()
	if c.p2pPeers != nil {
		delete(c.p2pPeers, ip)
	}
	c.p2pMu.Unlock()
}

// connectPeer attempts to dial a peer via QUIC P2P. Called when a new
// peer is discovered through signaling (RoomMembers or PeerJoin).
func (c *Client) connectPeer(pi protocol.PeerInfo) {
	if c.p2pMgr == nil || pi.StunEndpoint == "" {
		return
	}
	go func() {
		if err := c.p2pMgr.Dial(pi.IP, pi.StunEndpoint); err != nil {
			c.logger.Debug("p2p dial failed", "peer", pi.IP, "err", err)
		}
	}()
}

// P2PStats returns a summary string for the GUI status label.
func (c *Client) P2PStats() (knownPeers int, activeP2P int) {
	knownPeers = len(c.listPeerIPs())
	if c.p2pMgr != nil {
		activeP2P = c.p2pMgr.ActiveCount()
	}
	return
}

// peerFingerprint returns the ed25519 cert fingerprint for a known peer
// IP. Returns false if the peer is not in the registry or has no ed pubkey.
func (c *Client) peerFingerprint(ip string) (string, bool) {
	c.p2pMu.RLock()
	p, ok := c.p2pPeers[ip]
	c.p2pMu.RUnlock()
	if !ok || p == nil || p.EdPubkey == "" {
		return "", false
	}
	return shortFPFromHex(p.EdPubkey), true
}

// listPeerIPs returns all known peer IPs.
func (c *Client) listPeerIPs() []string {
	c.p2pMu.RLock()
	defer c.p2pMu.RUnlock()
	out := make([]string, 0, len(c.p2pPeers))
	for ip := range c.p2pPeers {
		out = append(out, ip)
	}
	return out
}

// Config is the tunelc runtime configuration.
type Config struct {
	Server      string
	Token       string
	Tunnels     []TunnelSpec
	CACert      string
	Insecure    bool
	MaxAttempts int
	OnEvent     func(Event)

	// P2P identity (only used in VPN mode)
	IdentityPubkeyHex  string // hex-encoded curve25519 public key
	IdentityPrivkeyHex string // hex-encoded curve25519 private key
	EdPubkeyHex        string // hex-encoded ed25519 public key (for TLS cert)
	EdPrivkeyHex       string // hex-encoded ed25519 private key (for TLS cert)
	StunServer         string // empty = auto (= server.domain:3478 or default)
	StunEndpoint       string // discovered by runtime probe, sent in Auth
	Room               string // VPN room to join (empty → "lobby")
	RoomPassword       string // room password for private rooms
}

// New constructs a Client. It does not connect; call Run (TCP/UDP tunnels)
// or RunVPN (Layer-3 VPN mode) to start the loop.
//
// Tunnels may be empty when the caller plans to use RunVPN (since VPN mode
// has no per-tunnel spec); it is validated at Run-time instead.
func New(cfg Config, logger *slog.Logger) (*Client, error) {
	if cfg.Server == "" {
		return nil, errors.New("client: --server is required")
	}
	if cfg.Token == "" {
		return nil, errors.New("client: --token is required")
	}
	for i, t := range cfg.Tunnels {
		if t.PublicPort <= 0 || t.PublicPort > 65535 {
			return nil, fmt.Errorf("client: tunnel %d: invalid public_port %d", i, t.PublicPort)
		}
		if t.LocalTarget == "" {
			return nil, fmt.Errorf("client: tunnel %d (port %d): --local is required", i, t.PublicPort)
		}
		if t.Proto != "tcp" && t.Proto != "udp" && t.Proto != "" {
			return nil, fmt.Errorf("client: tunnel %d: unsupported proto %q", i, t.Proto)
		}
	}
	if !cfg.Insecure && cfg.CACert == "" {
		return nil, errors.New("client: --cacert is required (or use --insecure)")
	}
	return &Client{
		logger: logger.With("component", "client"),
		cfg:    cfg,
	}, nil
}

// validateTunnels ensures cfg.Tunnels is non-empty and well-formed. Called by
// Run() at the start to provide an explicit error in the non-VPN path.
func (c *Client) validateTunnels() error {
	if len(c.cfg.Tunnels) == 0 {
		return errors.New("client: at least one --tunnel is required (or use --vpn)")
	}
	return nil
}

// Run blocks until ctx is canceled or the reconnection loop is exhausted.
func (c *Client) Run(ctx context.Context) error {
	if err := c.validateTunnels(); err != nil {
		return err
	}
	maxAttempts := c.cfg.MaxAttempts
	attempt := 0
	for {
		if ctx.Err() != nil {
			c.emit(StateStopped, "detenido")
			return nil
		}
		attempt++
		c.emit(StateConnecting, fmt.Sprintf("conectando a %s (intento %d, %d túneles)", c.cfg.Server, attempt, len(c.cfg.Tunnels)))
		err := c.runOnce(ctx)
		if err == nil {
			c.emit(StateStopped, "sesión cerrada")
			return nil
		}
		if ctx.Err() != nil {
			c.emit(StateStopped, "detenido")
			return nil
		}
		c.logger.Error("tunnel disconnected",
			"attempt", attempt,
			"max_attempts", maxAttempts,
			"err", err)

		if isAuthErr(err) {
			c.emit(StateError, "server rechazó el túnel: "+err.Error())
			return err
		}

		if maxAttempts > 0 && attempt >= maxAttempts {
			c.emit(StateError, fmt.Sprintf("se rindió tras %d intentos: %s", attempt, err))
			return fmt.Errorf("client: gave up after %d attempts: %w", attempt, err)
		}

		backoff := backoff(attempt)
		c.emit(StateReconnecting, fmt.Sprintf("reintentando en %s (%d)", backoff, attempt))
		c.logger.Info("reconnecting", "wait", backoff)
		select {
		case <-ctx.Done():
			c.emit(StateStopped, "detenido")
			return nil
		case <-time.After(backoff):
		}
	}
}

// session represents one established yamux session with its tunnels.
type session struct {
	ymx    *yamux.Session
	mu     sync.RWMutex
	tuns   map[uint16]*remoteTunnel
}

type remoteTunnel struct {
	spec     TunnelSpec
	local    string // localTarget
	proto    string
	name     string
}

func (c *Client) runOnce(ctx context.Context) error {
	conn, err := c.dial()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	ymx, err := yamux.Client(conn, yamuxCfg())
	if err != nil {
		return fmt.Errorf("yamux client: %w", err)
	}
	defer ymx.Close()

	sess := &session{ymx: ymx, tuns: make(map[uint16]*remoteTunnel)}

	// Open one control stream per tunnel.
	var wg sync.WaitGroup
	tunnelErrCh := make(chan error, len(c.cfg.Tunnels))
	for _, spec := range c.cfg.Tunnels {
		spec := spec
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.setupTunnel(ctx, sess, spec); err != nil {
				tunnelErrCh <- err
				return
			}
			c.logger.Info("tunnel established",
				"proto", spec.Proto,
				"public_port", spec.PublicPort,
				"local", spec.LocalTarget,
				"name", spec.Name)
		}()
	}
	wg.Wait()
	close(tunnelErrCh)
	for e := range tunnelErrCh {
		if e != nil {
			return e
		}
	}
	c.emit(StateConnected, fmt.Sprintf("%d túneles activos hacia %s", len(c.cfg.Tunnels), c.cfg.Server))

	// Accept data streams until the session dies.
	errCh := make(chan error, 1)
	go func() { errCh <- c.serveData(sess) }()

	select {
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	case <-ctx.Done():
		return nil
	}
}

// setupTunnel opens one control stream, sends Auth, expects AuthOK with a
// tunnel ID, registers the tunnel in the session, then starts a Ping loop.
func (c *Client) setupTunnel(ctx context.Context, sess *session, spec TunnelSpec) error {
	proto := spec.Proto
	if proto == "" {
		proto = "tcp"
	}
	control, err := sess.ymx.Open()
	if err != nil {
		return fmt.Errorf("open control stream for port %d: %w", spec.PublicPort, err)
	}
	// NOTE: we intentionally do NOT defer control.Close() here. The control
	// stream must stay open for the lifetime of the tunnel so the server's
	// serveControl loop keeps the public listener registered. The stream is
	// closed implicitly when the yamux session is torn down at runOnce end.

	if err := protocol.Encode(control, protocol.Auth{
		Type:        protocol.MsgAuth,
		Token:       c.cfg.Token,
		PublicPort:  spec.PublicPort,
		LocalTarget: spec.LocalTarget,
		Proto:       proto,
	}); err != nil {
		_ = control.Close()
		return fmt.Errorf("send auth: %w", err)
	}

	dec := protocol.NewDecoder(control)
	env, err := dec.ReadEnvelope()
	if err != nil {
		return fmt.Errorf("read auth reply: %w", err)
	}
	switch env.Type {
	case protocol.MsgAuthOK:
		var ok protocol.AuthOK
		_ = env.Bind(&ok)
		sess.mu.Lock()
		sess.tuns[ok.TunnelID] = &remoteTunnel{
			spec:  spec,
			local: spec.LocalTarget,
			proto: proto,
			name:  spec.Name,
		}
		sess.mu.Unlock()
	case protocol.MsgAuthErr:
		var e protocol.AuthErr
		_ = env.Bind(&e)
		_ = control.Close()
		return &authRejectionError{reason: e.Reason}
	default:
		_ = control.Close()
		return fmt.Errorf("unexpected auth reply type: %s", env.Type)
	}

	// Keep the control stream alive with Ping.
	go func() { _ = c.controlPings(ctx, control) }()
	return nil
}

// controlPings sends Ping frames every 30s over the control stream. Returns
// when the stream is closed (err) or ctx is canceled.
func (c *Client) controlPings(ctx context.Context, control io.ReadWriteCloser) error {
	dec := protocol.NewDecoder(control)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	errCh := make(chan error, 1)
	go func() {
		for {
			_, err := dec.ReadEnvelope()
			if err != nil {
				errCh <- err
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			if err == io.EOF {
				return nil
			}
			return err
		case <-t.C:
			if err := protocol.Encode(control, protocol.Ping{Type: protocol.MsgPing}); err != nil {
				return err
			}
		}
	}
}

// serveData drains incoming yamux streams (each one carrying public traffic for
// some tunnel). Returns on session error.
func (c *Client) serveData(sess *session) error {
	for {
		stream, err := sess.ymx.Accept()
		if err != nil {
			return fmt.Errorf("accept data stream: %w", err)
		}
		go c.handleData(sess, stream)
	}
}

func (c *Client) handleData(sess *session, stream net.Conn) {
	defer stream.Close()
	tid, err := protocol.ReadTunnelID(stream)
	if err != nil {
		c.logger.Error("read tunnel id", "err", err)
		return
	}
	sess.mu.RLock()
	tun, ok := sess.tuns[tid]
	sess.mu.RUnlock()
	if !ok {
		c.logger.Warn("data stream for unknown tunnel", "tunnel_id", tid)
		return
	}
	switch tun.proto {
	case "tcp":
		c.relayTCP(stream, tun.local)
	case "udp":
		c.relayUDP(stream, tun.local)
	default:
		c.relayTCP(stream, tun.local)
	}
}

// relayTCP forwards raw bytes between the yamux stream and a fresh TCP dial
// to the local target.
func (c *Client) relayTCP(stream net.Conn, local string) {
	dst, err := net.DialTimeout("tcp", local, 10*time.Second)
	if err != nil {
		c.logger.Error("dial local tcp", "target", local, "err", err)
		return
	}
	defer dst.Close()
	pipeBoth(stream, dst)
}

// relayUDP reads a HELLO frame (peer info, mostly informational), opens a UDP
// socket to the local target, then:
//   - stream frames -> local socket (deframed datagrams from outside world).
//   - local socket -> stream frames (responses from local game server).
func (c *Client) relayUDP(stream net.Conn, local string) {
	peer, err := protocol.ReadHelloFrame(stream)
	if err != nil {
		c.logger.Error("read udp hello", "err", err)
		return
	}
	c.logger.Debug("udp peer", "peer", peer, "local", local)

	localConn, err := net.Dial("udp", local)
	udpLocal, _ := localConn.(*net.UDPConn)
	if udpLocal == nil {
		// Fall back to PacketConn-style reads to be safe across implementations.
		udpLocal = maybeUDP(localConn)
	}
	if err != nil {
		c.logger.Error("dial local udp", "target", local, "err", err)
		return
	}
	defer localConn.Close()

	// stream -> local
	go func() {
		buf := make([]byte, protocol.MaxDatagramLen)
		for {
			ftype, payload, _, rerr := protocol.ReadFrame(stream, buf)
			if rerr != nil {
				return
			}
			switch ftype {
			case protocol.FrameDatagram:
				if len(payload) > 0 {
					_, _ = localConn.Write(payload)
				}
			case protocol.FrameGoodbye:
				return
			}
		}
	}()

	// local -> stream
	rbuf := make([]byte, protocol.MaxDatagramLen)
	for {
		n, rerr := localConn.Read(rbuf)
		if rerr != nil {
			return
		}
		if werr := protocol.WriteDatagramFrame(stream, rbuf[:n]); werr != nil {
			return
		}
	}
}

// maybeUDP returns the *net.UDPConn form of c, or nil when not a UDPConn.
func maybeUDP(c net.Conn) *net.UDPConn {
	if u, ok := c.(*net.UDPConn); ok {
		return u
	}
	return nil
}

// dial establishes the TLS control connection with CA pinning.
func (c *Client) dial() (net.Conn, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if c.cfg.Insecure {
		tlsCfg.InsecureSkipVerify = true
	} else {
		pem, err := os.ReadFile(c.cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read cacert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("no certs found in --cacert file")
		}
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, 0, len(raw))
			for _, b := range raw {
				cc, err := x509.ParseCertificate(b)
				if err != nil {
					return err
				}
				certs = append(certs, cc)
			}
			if len(certs) == 0 {
				return errors.New("no peer certs")
			}
			opts := x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}
			_, err := certs[0].Verify(opts)
			return err
		}
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", c.cfg.Server, tlsCfg)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// authRejectionError wraps server-side auth denials so Run treats them as
// fatal (no point retrying the same bad token).
type authRejectionError struct{ reason string }

func (e *authRejectionError) Error() string { return "server rejected tunnel: " + e.reason }

func isAuthErr(err error) bool {
	var a *authRejectionError
	return errors.As(err, &a)
}

// backoff returns an exponential backoff (in seconds) capped at 30s.
func backoff(attempt int) time.Duration {
	d := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// yamuxCfg returns the client-side yamux configuration, tuned symmetrically
// with the server.
func yamuxCfg() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.ConnectionWriteTimeout = 30 * time.Second
	return cfg
}