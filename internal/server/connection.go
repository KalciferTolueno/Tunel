package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/hashicorp/yamux"

	"tunel/internal/protocol"
)

// Connection represents one tunelc connected to the server via a TLS+ yamux
// session. A Connection owns many tunnels, each requested by a separate
// control stream opened by the client. The Connection assigns each tunnel a
// 16-bit TunnelID and registers it so data streams can be demultiplexed.
type Connection struct {
	srv     *Server
	ymx     *yamux.Session
	logger  *slog.Logger
	id      string

	mu      sync.Mutex
	tunnels map[uint16]*Tunnel // by tunnel ID
	ports   map[int]*Tunnel    // by public port (for uniqueness check)
	nextID  uint16
	closed  bool
}

func newConnection(srv *Server, ymx *yamux.Session, logger *slog.Logger) *Connection {
	return &Connection{
		srv:     srv,
		ymx:     ymx,
		logger:  logger,
		id:      newConnID(),
		tunnels: make(map[uint16]*Tunnel),
		ports:   make(map[int]*Tunnel),
		nextID:  1,
	}
}

// run accepts yamux streams from the client. The first byte of every stream
// is a kind discriminator:
//   - '{' (0x7B, JSON)  -> control stream carrying Auth/Ping frames.
//   - 0x9A (VPN magic)  -> VPN packet stream carrying length-prefixed IP packets.
//
// Returns when the yamux session ends or ctx is canceled.
func (c *Connection) run(ctx context.Context) {
	c.logger = c.logger.With("conn", c.id)
	c.logger.Info("tunelc connected")

	// Reaper for dead UDP peers / idle TCP conns.
	go c.reaper(ctx)

	for {
		stream, err := c.ymx.Accept()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, yamux.ErrSessionShutdown) {
				c.logger.Info("accept ended", "err", err)
			} else {
				c.logger.Info("tunelc disconnected")
			}
			c.closeAll()
			if hub := c.srv.vpn(); hub != nil {
				hub.releasePeer(c)
			}
			return
		}
		go c.handleStream(ctx, stream)
	}
}

// handleStream peeks the first byte of an inbound yamux stream and dispatches
// it to the appropriate handler.
func (c *Connection) handleStream(ctx context.Context, stream net.Conn) {
	var first [1]byte
	if _, err := io.ReadFull(stream, first[:]); err != nil {
		_ = stream.Close()
		return
	}
	switch first[0] {
	case protocol.PacketStreamMagic:
		// VPN packet stream. Verify the magic is followed by nothing else
		// (the client immediately starts writing length-prefixed packets).
		c.handleVPNPackets(ctx, stream)
		return
	default:
		// Assume control stream (JSON). Restore the consumed byte by feeding
		// it back to the decoder through a MultiReader.
		restored := io.MultiReader(bytes.NewReader(first[:]), stream)
		c.handleControl(ctx, stream, restored)
	}
}

// handleVPNPackets associates an accepted VPN packet stream with the peer owning
// this connection and lets the hub route packets through it. The stream is
// kept open for the lifetime of the peer.
func (c *Connection) handleVPNPackets(ctx context.Context, stream net.Conn) {
	hub := c.srv.vpn()
	if hub == nil {
		_ = stream.Close()
		return
	}
	if err := hub.attachPacketStream(c, stream); err != nil {
		c.logger.Warn("vpn packet stream rejected", "err", err)
		_ = stream.Close()
		return
	}
	// attachPacketStream starts its own readLoop; nothing more to do here.
	_ = ctx
}

// handleControl reads one Auth frame over a freshly-opened control stream,
// sets up a Tunnel (TCP/UDP) or a VPN peer for it, and demuxes ongoing
// Ping/Pong frames on that same stream until the tunnel ends.
//
// The `restored` reader is the control stream with the kind-discriminator
// byte already consumed and re-prepended (so protocol.NewDecoder sees the
// leading `{` of the JSON envelope).
func (c *Connection) handleControl(ctx context.Context, control net.Conn, restored io.Reader) {
	defer control.Close()
	dec := protocol.NewDecoder(restored)

	env, err := dec.ReadEnvelope()
	if err != nil {
		c.logger.Error("read auth", "err", err)
		return
	}
	if env.Type != protocol.MsgAuth {
		_ = protocol.Encode(control, protocol.AuthErr{Type: protocol.MsgAuthErr, Reason: "first frame must be auth"})
		return
	}
	var auth protocol.Auth
	if err := env.Bind(&auth); err != nil {
		_ = protocol.Encode(control, protocol.AuthErr{Type: protocol.MsgAuthErr, Reason: "bad auth payload"})
		return
	}

	proto, ok := validProto(auth.Proto)
	if !ok {
		_ = protocol.Encode(control, protocol.AuthErr{Type: protocol.MsgAuthErr, Reason: "unsupported proto: " + auth.Proto})
		return
	}
	if auth.Token != c.srv.cfg.Token {
		c.logger.Warn("auth bad token", "proto", proto, "port", auth.PublicPort)
		_ = protocol.Encode(control, protocol.AuthErr{Type: protocol.MsgAuthErr, Reason: "bad token"})
		return
	}

	if proto == "vpn" {
		c.handleVPNAuth(ctx, control, auth)
		return
	}

	// Legacy TCP/UDP code path.
	if auth.PublicPort <= 0 || auth.PublicPort > 65535 {
		_ = protocol.Encode(control, protocol.AuthErr{Type: protocol.MsgAuthErr, Reason: "invalid public_port"})
		return
	}
	if !c.srv.portAllowed(auth.PublicPort) {
		c.logger.Warn("auth port not allowed", "port", auth.PublicPort)
		_ = protocol.Encode(control, protocol.AuthErr{Type: protocol.MsgAuthErr, Reason: "public_port not allowed"})
		return
	}

	tun, err := c.grantTunnel(ctx, control, proto, auth)
	if err != nil {
		c.logger.Error("grant tunnel", "err", err)
		_ = protocol.Encode(control, protocol.AuthErr{Type: protocol.MsgAuthErr, Reason: err.Error()})
		return
	}

	c.logger.Info("tunnel granted",
		"proto", proto,
		"public_port", auth.PublicPort,
		"local_target", auth.LocalTarget,
		"tunnel_id", tun.id,
	)

	defer c.releaseTunnel(tun)
	tun.serveControl(ctx)
}

// handleVPNAuth allocates a VPN peer for this connection, acks with assigned
// IP/mask/gateway/subnet, and then keeps the control stream alive returning
// pings until the client disconnects (which triggers peer release).
func (c *Connection) handleVPNAuth(ctx context.Context, control net.Conn, auth protocol.Auth) {
	hub := c.srv.vpn()
	if hub == nil {
		_ = protocol.Encode(control, protocol.AuthErr{Type: protocol.MsgAuthErr, Reason: "VPN mode disabled on this server"})
		return
	}
	roomName := auth.Room
	if roomName == "" {
		roomName = "lobby"
	}
	peer, err := hub.grantPeer(c, roomName, auth.RoomPassword, auth.IdentityPubkey, auth.EdPubkey, auth.StunEndpoint)
	if err != nil {
		c.logger.Error("vpn grant peer", "room", roomName, "err", err)
		_ = protocol.Encode(control, protocol.AuthErr{Type: protocol.MsgAuthErr, Reason: err.Error()})
		return
	}
	defer hub.releasePeer(c)

	room := peer.room
	gw := room.gatewayIP()
	gwStr := net.IP(gw[:]).String()

	if err := protocol.Encode(control, protocol.AuthOK{
		Type:       protocol.MsgAuthOK,
		SessionID:  c.id,
		TunnelID:   uint16(peer.ip[3]),
		VPNIP:      net.IP(peer.ip[:]).String(),
		VPNMask:    room.maskDotted(),
		VPNGateway: gwStr,
		VPNSubnet:  room.cidr(),
		Room:       roomName,
		RoomSize:   room.size(),
	}); err != nil {
		c.logger.Error("send vpn auth_ok", "err", err)
		return
	}
	c.logger.Info("vpn peer granted",
		"room", roomName,
		"ip", net.IP(peer.ip[:]).String(),
		"tunnel_id", peer.ip[3],
	)

	peer.ctrl = control
	hub.sendRoomMembers(peer)
	hub.notifyJoin(peer, room)

	// Ping loop on control stream until client disconnects.
	dec := protocol.NewDecoder(control)
	for {
		env, rerr := dec.ReadEnvelope()
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) && !errors.Is(rerr, net.ErrClosed) {
				c.logger.Info("vpn control stream ended", "err", rerr)
			}
			return
		}
		switch env.Type {
		case protocol.MsgPing:
			_ = protocol.Encode(control, protocol.Pong{Type: protocol.MsgPong})
		default:
			// ignore other frames in MVP
		}
		_ = ctx
	}
}

// grantTunnel allocates the Tunnel record, opens the public listener, and
// sends AuthOK with the assigned tunnel ID.
func (c *Connection) grantTunnel(ctx context.Context, control net.Conn, proto string, auth protocol.Auth) (*Tunnel, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("connection closing")
	}
	if _, dup := c.ports[auth.PublicPort]; dup {
		c.mu.Unlock()
		return nil, fmt.Errorf("public_port %d already in use on this server", auth.PublicPort)
	}
	id := c.nextID
	c.nextID++
	tun := &Tunnel{
		id:           id,
		proto:        proto,
		publicPort:   auth.PublicPort,
		localTarget:  auth.LocalTarget,
		conn:         c,
		control:      control,
		controlDec:   protocol.NewDecoder(control),
		closed:       make(chan struct{}),
		logger:       c.logger.With("tunnel", id, "proto", proto, "port", auth.PublicPort),
	}
	c.tunnels[id] = tun
	c.ports[auth.PublicPort] = tun
	c.mu.Unlock()

	// Open public listener BEFORE acking so we fail fast if the port is busy.
	if err := tun.openPublic(); err != nil {
		c.mu.Lock()
		delete(c.tunnels, id)
		delete(c.ports, auth.PublicPort)
		c.mu.Unlock()
		return nil, err
	}

	// Acknowledge.
	if err := protocol.Encode(control, protocol.AuthOK{
		Type:      protocol.MsgAuthOK,
		SessionID: c.id,
		TunnelID:  id,
	}); err != nil {
		tun.closePublic()
		c.mu.Lock()
		delete(c.tunnels, id)
		delete(c.ports, auth.PublicPort)
		c.mu.Unlock()
		return nil, fmt.Errorf("send auth_ok: %w", err)
	}

	return tun, nil
}

// releaseTunnel removes a tunnel from the connection's registry and closes its
// public listener. Safe to call multiple times (idempotent via closeOnce).
func (c *Connection) releaseTunnel(t *Tunnel) {
	c.mu.Lock()
	delete(c.tunnels, t.id)
	delete(c.ports, t.publicPort)
	c.mu.Unlock()
	t.closePublic()
}

// closeAll terminates every tunnel owned by this connection. Called when the
// underlying yamux session ends.
func (c *Connection) closeAll() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	all := make([]*Tunnel, 0, len(c.tunnels))
	for _, t := range c.tunnels {
		all = append(all, t)
	}
	c.tunnels = make(map[uint16]*Tunnel)
	c.ports = make(map[int]*Tunnel)
	c.mu.Unlock()

	for _, t := range all {
		t.closePublic()
	}
}

// reaper currently just logs active tunnel count periodically. UDP peer idle
// timeouts are handled per tunnel (udpPeer struct).
func (c *Connection) reaper(ctx context.Context) {
	<-ctx.Done()
	c.closeAll()
}

// newConnID returns a short random hex identifier for a tunelc connection.
func newConnID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}