package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"

	"tunel/internal/protocol"
)

// Tunnel is one granted forwarding rule inside a Connection: a public listener
// (TCP or UDP) plus the controlling stream (Ping) back to the client.
type Tunnel struct {
	id          uint16
	proto       string
	publicPort  int
	localTarget string
	conn        *Connection
	control     net.Conn
	controlDec  *protocol.Decoder

	mu         sync.Mutex
	closed     chan struct{}
	closeOnce  sync.Once
	logger     *slog.Logger

	// TCP: net.Listener on the public port. UDP: net.PacketConn.
	tcpLn      net.Listener
	udpLn      net.PacketConn

	// UDP peer bookkeeping. Each public peer -> one open yamux data stream
	// + goroutine reading frames back from the client.
	udpPeers   map[string]*udpPeer
	udpGroup   sync.WaitGroup
	udpMu      sync.Mutex
}

// openPublic starts listening on the public port according to the tunnel's
// proto. On success the tunnel is live and ready to accept data streams.
func (t *Tunnel) openPublic() error {
	switch t.proto {
	case "tcp":
		ln, err := net.Listen("tcp", addrFor(t.publicPort))
		if err != nil {
			return err
		}
		t.tcpLn = ln
		go t.acceptTCP()
	case "udp":
		pc, err := net.ListenPacket("udp", addrFor(t.publicPort))
		if err != nil {
			return err
		}
		t.udpLn = pc
		t.udpPeers = make(map[string]*udpPeer)
		go t.serveUDP()
	}
	return nil
}

// closePublic stops the public listener and (for UDP) tears down peer streams.
func (t *Tunnel) closePublic() {
	t.closeOnce.Do(func() {
		close(t.closed)
		if t.tcpLn != nil {
			_ = t.tcpLn.Close()
		}
		if t.udpLn != nil {
			_ = t.udpLn.Close()
		}
		t.udpMu.Lock()
		for _, p := range t.udpPeers {
			_ = p.stream.Close()
		}
		t.udpPeers = make(map[string]*udpPeer)
		t.udpMu.Unlock()
	})
}

// serveControl keeps the control stream alive: replying to Pings, surfacing
// errors/closure to the connection handler. Returns when the stream closes.
func (t *Tunnel) serveControl(ctx context.Context) {
	for {
		env, err := t.controlDec.ReadEnvelope()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			t.logger.Info("control stream ended", "err", err)
			return
		}
		switch env.Type {
		case protocol.MsgPing:
			_ = protocol.Encode(t.control, protocol.Pong{Type: protocol.MsgPong})
		case protocol.MsgPong:
			// Server-initiated pings are not used in MVP.
		case protocol.MsgGoodbye:
			// no-op
		default:
			t.logger.Warn("unexpected control frame", "type", env.Type)
			// also continue for older protocol noise
		}
		_ = ctx
	}
}

// acceptTCP is the public TCP listener loop. For each inbound public
// connection it opens a yamux data stream, writes the 2-byte TunnelID, and
// pipes raw bytes both ways.
func (t *Tunnel) acceptTCP() {
	for {
		pub, err := t.tcpLn.Accept()
		if err != nil {
			return
		}
		go t.handleTCPConn(pub)
	}
}

func (t *Tunnel) handleTCPConn(pub net.Conn) {
	defer pub.Close()
	stream, err := t.conn.ymx.Open()
	if err != nil {
		t.logger.Error("open data stream", "err", err)
		return
	}
	defer stream.Close()

	if err := protocol.WriteTunnelID(stream, t.id); err != nil {
		t.logger.Error("write tunnel id", "err", err)
		return
	}

	t.logger.Debug("tcp tunnel conn", "remote", pub.RemoteAddr())

	go func() { _, _ = io.Copy(stream, pub); tryCloseWrite(stream) }()
	_, _ = io.Copy(pub, stream)
	tryCloseWrite(pub)
}

var _ slog.Leveler = (slog.Level)(0)

// tryCloseWrite is a best-effort CloseWrite so the other end's io.Copy returns
// promptly. Many net.Conn implementations support CloseWrite; we degrade to a
// full Close when they don't.
func tryCloseWrite(c io.Writer) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// addrFor formats the bind address for a TCP/UDP listener on the public port.
// We bind to all interfaces ("0.0.0.0") so the public internet can reach us;
// tunels admins are expected to firewall accordingly.
func addrFor(port int) string { return "0.0.0.0:" + itoa(port) }

// itoa is a tiny stdlib-free int->string helper used in hot paths where
// casting strconv.Itoa around would add noise; falls back to strconv semantics.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}