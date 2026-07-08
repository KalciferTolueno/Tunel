package server

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"tunel/internal/protocol"
)

// udpPeer represents an active public UDP peer. The server opens one yamux
// data stream per peer, sends a HELLO frame with the peer address, then
// forwards datagrams in both directions using length-prefixed frames.
type udpPeer struct {
	addr     *net.UDPAddr
	stream   net.Conn
	lastSeen time.Time
	closeOnce sync.Once
}

// serveUDP reads packets from the public UDP listener. For each new peer (by
// remote address) it opens a yamux data stream, writes the TunnelID + HELLO,
// and starts a return-direction goroutine that drains frames from the stream
// and writes them back to the peer.
func (t *Tunnel) serveUDP() {
	buf := make([]byte, protocol.MaxDatagramLen)
	for {
		n, peer, err := t.udpLn.ReadFrom(buf)
		if err != nil {
			return
		}
		peerAddr, ok := peer.(*net.UDPAddr)
		if !ok {
			continue
		}
		key := peerAddr.String()

		t.udpMu.Lock()
		p, exists := t.udpPeers[key]
		if !exists {
			stream, err := t.conn.ymx.Open()
			if err != nil {
				t.udpMu.Unlock()
				t.logger.Error("open udp data stream", "err", err)
				continue
			}
			if err := protocol.WriteTunnelID(stream, t.id); err != nil {
				_ = stream.Close()
				t.udpMu.Unlock()
				continue
			}
			if err := protocol.WriteHelloFrame(stream, key); err != nil {
				_ = stream.Close()
				t.udpMu.Unlock()
				continue
			}
			p = &udpPeer{addr: peerAddr, stream: stream, lastSeen: time.Now()}
			t.udpPeers[key] = p
			t.udpGroup.Add(1)
			go t.pumpUDPBack(p)
		}
		p.lastSeen = time.Now()
		t.udpMu.Unlock()

		// Frame copy: we must NOT share buf with the return goroutine since
		// the next ReadFrom may overwrite it. Make a copy.
		payload := make([]byte, n)
		copy(payload, buf[:n])
		if err := protocol.WriteDatagramFrame(p.stream, payload); err != nil {
			t.evictUDP(key, p)
		}
	}
}

// pumpUDPBack reads DATAGRAM frames from the client (responses coming from
// the local game server) and writes them back to the public peer.
func (t *Tunnel) pumpUDPBack(p *udpPeer) {
	defer t.udpGroup.Done()
	defer t.evictUDP(p.addr.String(), p)

	buf := make([]byte, protocol.MaxDatagramLen)
	for {
		ftype, payload, _, err := protocol.ReadFrame(p.stream, buf)
		if err != nil {
			return
		}
		switch ftype {
		case protocol.FrameDatagram:
			if len(payload) == 0 {
				continue
			}
			if _, err := t.udpLn.WriteTo(payload, p.addr); err != nil {
				return
			}
		case protocol.FrameGoodbye:
			return
		}
		// Trigger peer eviction by close reader side; stream EOF propagates.
		_ = io.EOF
	}
}

// evictUDP removes a peer from the peer table and closes its stream.
func (t *Tunnel) evictUDP(key string, p *udpPeer) {
	p.closeOnce.Do(func() {
		t.udpMu.Lock()
		if cur, ok := t.udpPeers[key]; ok && cur == p {
			delete(t.udpPeers, key)
		}
		t.udpMu.Unlock()
		_ = p.stream.Close()
	})
}

// ensure build doesn't complain about unused. Kept as the only error sentinels.
var _ = errors.New