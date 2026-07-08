//go:build vpn

// vpn.go implements the client side of the Layer-3 VPN tunnel. It is only
// compiled when the binary is built with the `vpn` tag, which requires a C
// toolchain on Windows (MinGW-w64 for wintun via the wireguard/tun package).
//
// Lifecycle:
//  1. dial TLS to tunels with proto="vpn" over a control yamux stream.
//  2. Read AuthOK carrying assigned VPNIP / VPNMask / VPNGateway / VPNSubnet.
//  3. Materialize wintun.dll next to the .exe (Windows only) and open a TUN
//     device via golang.zx2c4.com/wireguard/tun.
//  4. Configure the OS interface: assign the assigned IP/mask and set the
//     interface up. OS-specific helpers live in tun_windows.go / tun_unix.go.
//  5. Open a fresh yamux stream, write the 0x9A magic, then pump:
//        TUN.Read  -> protocol.WritePacket -> stream
//        stream     -> protocol.ReadPacket  -> TUN.Write
//  6. On ctx cancel or stream/TUN error: gracefully close everything.
//
// All events are surfaced via the OnEvent callback (same channel the regular
// tunnel client uses) so the GUI / CLI see the VPN state transitions.

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hashicorp/yamux"

	"tunel/internal/crypto"
	"tunel/internal/protocol"
)

// runVPN performs a single VPN connect-handshake-serve cycle. Called by
// Run() when --vpn was set on the CLI.
func (c *Client) runOnceVPN(ctx context.Context) error {
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

	// Open control stream; first byte must be the JSON envelope's leading
	// '{' (the server peeks it as a kind discriminator).
	control, err := ymx.Open()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	defer control.Close()

	if err := protocol.Encode(control, protocol.Auth{
		Type:            protocol.MsgAuth,
		Token:           c.cfg.Token,
		Proto:           "vpn",
		IdentityPubkey:  c.cfg.IdentityPubkeyHex,
		EdPubkey:        c.cfg.EdPubkeyHex,
		StunEndpoint:    c.cfg.StunEndpoint,
		Room:            c.cfg.Room,
		RoomPassword:    c.cfg.RoomPassword,
	}); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	dec := protocol.NewDecoder(control)
	env, err := dec.ReadEnvelope()
	if err != nil {
		return fmt.Errorf("read auth reply: %w", err)
	}
	if env.Type == protocol.MsgAuthErr {
		var e protocol.AuthErr
		_ = env.Bind(&e)
		return &authRejectionError{reason: e.Reason}
	}
	if env.Type != protocol.MsgAuthOK {
		return fmt.Errorf("unexpected auth reply type: %s", env.Type)
	}
	var ok protocol.AuthOK
	_ = env.Bind(&ok)
	if ok.VPNIP == "" {
		return errors.New("server did not return vpn_ip; VPN mode disabled?")
	}
	c.logger.Info("vpn assigned", "ip", ok.VPNIP, "mask", ok.VPNMask, "gateway", ok.VPNGateway, "subnet", ok.VPNSubnet)
	c.emit(StateConnecting, fmt.Sprintf("IP asignada %s/%s", ok.VPNIP, ok.VPNMask))

	// Open packet stream; write the magic byte right away so the server
	// recognises this is a VPN packet stream and not another control JSON
	// stream.
	pktStream, err := ymx.Open()
	if err != nil {
		return fmt.Errorf("open packet stream: %w", err)
	}
	if err := protocol.WritePacketStreamMagic(pktStream); err != nil {
		_ = pktStream.Close()
		return fmt.Errorf("write packet magic: %w", err)
	}

	// Open TUN device and configure it.
	dev, err := openTUN(ok)
	if err != nil {
		_ = pktStream.Close()
		return fmt.Errorf("open tun: %w", err)
	}
	defer dev.Close()

	if err := configureTUN(dev, ok); err != nil {
		return fmt.Errorf("configure tun: %w", err)
	}

	c.emit(StateConnected, fmt.Sprintf("VPN activa: %s en interfaz %s", ok.VPNIP, mustTunName(dev)))

	// Start QUIC P2P manager (if ed25519 key present).
	edPriv, p2pErr := crypto.EDPrivKeyFromHex(c.cfg.EdPrivkeyHex)
	if p2pErr == nil && edPriv != nil {
		certPEM, keyPEM, certErr := crypto.SelfSignedTLSCert(edPriv)
		if certErr == nil {
			tw := func(pkt []byte) error { _, werr := dev.Write(pkt, 0); return werr }
			mgr := newP2PManager(c.logger, c.peerFingerprint, c.listPeerIPs, tw)
			if startErr := mgr.Start(certPEM, keyPEM, ok.VPNIP); startErr != nil {
				c.logger.Warn("p2p start failed", "err", startErr)
			} else {
				c.p2pMgr = mgr
				c.logger.Info("p2p manager started", "vpn_ip", ok.VPNIP)
				defer c.p2pMgr.Stop()
			}
		} else {
			c.logger.Warn("tls cert gen failed", "err", certErr)
		}
	}

	// Control reader: handles pings replies + P2P signaling (RoomMembers, PeerJoin, PeerLeave).
	go func() { _ = c.vpnControlReader(ctx, control) }()

	// Pump: TUN <-> packet stream.
	errCh := make(chan error, 2)
	go func() { errCh <- c.tunToStream(ctx, dev, pktStream) }()
	go func() { errCh <- c.streamToTun(ctx, dev, pktStream) }()

	// Wait for either pump to finish.
	select {
	case err := <-errCh:
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
			return nil
		}
		return err
	case <-ctx.Done():
		return nil
	}
}

// tunToStream reads IP packets from the TUN device and writes them framed
// to the packet yamux stream. Packets to known P2P peers go via QUIC
// directly (skipping the relay) if a p2pManager is active.
func (c *Client) tunToStream(ctx context.Context, dev TUNDevice, stream io.Writer) error {
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := dev.Read(buf, 0)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return nil
			}
			return nil
		}
		if n == 0 {
			continue
		}
		pkt := buf[:n]
		// P2P direct routing: skip yamux relay if peer is connected.
		if c.p2pMgr != nil {
			if dst, ok := protocol.IPv4Dst(pkt); ok {
				dstStr := net.IP(dst[:]).String()
				if c.p2pMgr.Route(dstStr, pkt) {
					continue
				}
			}
		}
		if err := protocol.WritePacket(stream, pkt); err != nil {
			return fmt.Errorf("stream write: %w", err)
		}
	}
}

// streamToTun reads framed packets from the yamux stream and writes them to
// the TUN device.
func (c *Client) streamToTun(ctx context.Context, dev TUNDevice, stream io.Reader) error {
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := protocol.ReadPacket(stream, buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return fmt.Errorf("stream read: %w", err)
		}
		if n == 0 {
			continue
		}
		if _, err := dev.Write(buf[:n], 0); err != nil {
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("tun write: %w", err)
		}
	}
}

// -----------------------------------------------------------------------------
// RunVPN public API used by the CLI/GUI when --vpn is set.

// RunVPN is the outer reconnection loop for VPN mode. Equivalent to Run() but
// calls runOnceVPN instead of runOnce, and pins the message flavour of the
// events emitted to observers.
func (c *Client) RunVPN(ctx context.Context) error {
	maxAttempts := c.cfg.MaxAttempts
	attempt := 0
	for {
		if ctx.Err() != nil {
			c.emit(StateStopped, "detenido")
			return nil
		}
		attempt++
		c.emit(StateConnecting, fmt.Sprintf("conectando VPN a %s (intento %d)", c.cfg.Server, attempt))
		err := c.runOnceVPN(ctx)
		if err == nil {
			c.emit(StateStopped, "sesión VPN cerrada")
			return nil
		}
		if ctx.Err() != nil {
			c.emit(StateStopped, "detenido")
			return nil
		}
		c.logger.Error("vpn disconnected", "attempt", attempt, "max_attempts", maxAttempts, "err", err)

		if isAuthErr(err) {
			c.emit(StateError, "server rechazó VPN: "+err.Error())
			return err
		}
		if maxAttempts > 0 && attempt >= maxAttempts {
			c.emit(StateError, fmt.Sprintf("VPN se rindió tras %d intentos: %s", attempt, err))
			return fmt.Errorf("client: gave up after %d attempts: %w", attempt, err)
		}
		bo := backoff(attempt)
		c.emit(StateReconnecting, fmt.Sprintf("reintentando en %s", bo))
		select {
		case <-ctx.Done():
			c.emit(StateStopped, "detenido")
			return nil
		case <-time.After(bo):
		}
	}
}

// -----------------------------------------------------------------------------
// OS-agnostic TUNDevice wrapper.
// wireguard/tun already returns a tun.Device interface that is cross-OS. We
// wrap it minimally so that vpn.go can be written without the wireguard import
// here (it lives in tun_windows.go / tun_unix.go instead).

// TUNDevice is the minimal subset of tun.Device that the VPN client uses.
// Methods mirror wireguard/tun's signatures (Read/Write block until data or
// close; there's no per-call timeout — closing the device cancels the pump).
type TUNDevice interface {
	Name() (string, error)
	Read(buf []byte, off int) (int, error)
	Write(buf []byte, off int) (int, error)
	Close() error
	Events() <-chan TunEvent
	MTU() (int, error)
}

// TunEvent is the minimal subset of tun.Event we surface to callers; we
// never expose the upstream enum directly to keep imports confined to the
// OS files (named TunEvent to avoid colliding with the OnEvent Event struct
// defined in state.go).
type TunEvent int

const (
	TunEventUp TunEvent = 1 << iota
	TunEventDown
)

// -----------------------------------------------------------------------------
// OS-specific helpers live in tun_windows.go / tun_unix.go. They expose:
//
//   func openTUN(ok protocol.AuthOK) (TUNDevice, error)
//   func configureTUN(dev TUNDevice, ok protocol.AuthOK) error

// Helpers shared across OS files. They exec user-facing commands and log
// once per command. Each helper returns wrapped errors.

// runCmdLines executes the given shell fragments using `sh -c` (Linux/macOS)
// or PowerShell (Windows via tun_windows.go).
func runCmdLines(cmds [][]string, logFn func(string, ...any)) error {
	for _, c := range cmds {
		var name string
		var args []string
		if runtime.GOOS == "windows" {
			name = "powershell"
			args = append([]string{"-NoProfile", "-Command"}, c...)
		} else {
			name = "sh"
			args = append([]string{"-c"}, strings.Join(c, " && "))
		}
		cmd := exec.Command(name, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("cmd %q: %w: %s", c, err, out)
		}
		logFn("ran", "cmd", c)
	}
	return nil
}

// exeDir returns the directory of the running .exe/.out binary. Used on
// Windows to know where to drop wintun.dll next to it.
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// mustTunName returns the TUN device's name or "<unknown>" if listing fails.
func mustTunName(dev TUNDevice) string {
	name, err := dev.Name()
	if err != nil {
		return "<unknown>"
	}
	return name
}

// vpnControlReader reads control frames on the VPN control stream: it
// responds to Pongs, updates the peer registry from signaling messages
// (RoomMembers, PeerJoin, PeerLeave), and returns when the stream is closed.
func (c *Client) vpnControlReader(ctx context.Context, control io.ReadWriteCloser) error {
	dec := protocol.NewDecoder(control)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()

	for {
		// Non-blocking receive with a short timeout so the ping ticker can fire.
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if err := protocol.Encode(control, protocol.Ping{Type: protocol.MsgPing}); err != nil {
				return err
			}
		default:
		}

		env, err := dec.ReadEnvelope()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		switch env.Type {
		case protocol.MsgPong:
			// no-op; keepalive acknowledged.
		case protocol.MsgRoomMembers:
			var m protocol.RoomMembers
			if bindErr := env.Bind(&m); bindErr == nil {
				for _, pi := range m.Peers {
					c.storePeer(pi)
				}
				for _, pi := range m.Peers {
					c.connectPeer(pi)
				}
			}
		case protocol.MsgPeerJoin:
			var j protocol.PeerJoin
			if bindErr := env.Bind(&j); bindErr == nil {
				c.storePeer(j.Peer)
				c.logger.Info("peer joined", "ip", j.Peer.IP, "pubkey_pfx", j.Peer.Pubkey[:min(8, len(j.Peer.Pubkey))])
				c.connectPeer(j.Peer)
			}
		case protocol.MsgPeerLeave:
			var l protocol.PeerLeave
			if bindErr := env.Bind(&l); bindErr == nil {
				c.removePeer(l.IP)
				c.logger.Info("peer left", "ip", l.IP)
			}
		default:
			// Ignore other control frames in VPN mode.
		}
		_ = ctx
	}
}