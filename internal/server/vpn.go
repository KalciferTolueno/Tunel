// vpn.go implements the server-side Layer-3 VPN hub with room isolation.

package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"tunel/internal/protocol"
)

// vpnHub holds all rooms and orchestrates routing between peers inside
// each room. Rooms provide subnet isolation: broadcasts only reach
// peers of the same room; unicast is also restricted per room.
type vpnHub struct {
	logger *slog.Logger
	mu     sync.RWMutex
	rooms  map[string]*Room // name → room
	// subnetAlloc tracks the next /24 subnet to assign to a new room.
	// 0 = 10.99.0.0/24 (lobby), 1 = 10.99.1.0/24, ...
	nextSubnet byte
}

// vpnPeer is one connected tunelc --vpn client.
type vpnPeer struct {
	room         *Room
	ip           [4]byte
	str          net.IP
	conn         *Connection
	pkts         net.Conn
	ctrl         net.Conn
	log          *slog.Logger
	close        sync.Once
	pubkey       string
	edPubkey     string
	stunEndpoint string
	txPackets    atomic.Int64
	rxPackets    atomic.Int64
}

func (p *vpnPeer) cleanup() {
	p.close.Do(func() {
		if p.pkts != nil {
			_ = p.pkts.Close()
		}
		p.log.Info("peer left vpn")
	})
}

func newVPNHub(logger *slog.Logger) (*vpnHub, error) {
	h := &vpnHub{
		logger: logger.With("component", "vpn"),
		rooms:  make(map[string]*Room),
	}
	if _, err := h.ensureRoom("lobby", "", false); err != nil {
		return nil, fmt.Errorf("create lobby room: %w", err)
	}
	return h, nil
}

// ensureRoom returns an existing room or creates one when name is new.
// privateWide and password control privacy; the first person in creates the room.
func (h *vpnHub) ensureRoom(name, password string, private bool) (*Room, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if r, exists := h.rooms[name]; exists {
		if r.Private && r.Password != password {
			return nil, errors.New("bad room password")
		}
		return r, nil
	}
	subnet := h.allocSubnet()
	r, err := newRoom(name, subnet, private, password)
	if err != nil {
		return nil, err
	}
	h.rooms[name] = r
	h.logger.Info("room created", "room", name, "subnet", r.cidr())
	return r, nil
}

func (h *vpnHub) allocSubnet() *net.IPNet {
	// 10.99.X.0/24 where X = nextSubnet (incremented each call)
	// For X=0 (lobby), this gives 10.99.0.0/24.
	x := h.nextSubnet
	h.nextSubnet++
	ip := net.IPv4(10, 99, x, 0)
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(24, 32)}
}

// grantPeer adds a peer to the given room and allocates an IP.
func (h *vpnHub) grantPeer(conn *Connection, roomName, roomPass string, pubkey, edPubkey, endpoint string) (*vpnPeer, error) {
	private := roomPass != ""
	room, err := h.ensureRoom(roomName, roomPass, private)
	if err != nil {
		return nil, err
	}
	p, err := room.grantPeer(conn, pubkey, edPubkey, endpoint)
	if err != nil {
		return nil, err
	}
	p.log = h.logger.With("room", roomName, "peer", net.IP(p.ip[:]).String())
	return p, nil
}

// releasePeer removes a peer. It searches all rooms — only one can own it.
func (h *vpnHub) releasePeer(conn *Connection) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, r := range h.rooms {
		if p := r.releasePeer(conn); p != nil {
			return
		}
	}
}

// Packet routing delegates to the peer's room.
func (h *vpnHub) route(pkt []byte, from *vpnPeer) {
	if from.room != nil {
		from.room.route(pkt, from)
	}
}

// attachPacketStream stores the packet stream on the peer.
func (h *vpnHub) attachPacketStream(conn *Connection, stream net.Conn) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, r := range h.rooms {
		r.mu.Lock()
		p, ok := r.byConn[conn]
		r.mu.Unlock()
		if ok && p != nil {
			p.pkts = stream
			go p.readLoop(stream)
			h.logger.Info("packet stream attached", "room", r.Name, "peer", net.IP(p.ip[:]).String())
			return nil
		}
	}
	return errors.New("no vpn peer for connection")
}

// readLoop pulls packets from a peer and routes them via peer's room.
func (p *vpnPeer) readLoop(stream net.Conn) {
	buf := make([]byte, protocol.MaxPacketLen)
	for {
		n, err := protocol.ReadPacket(stream, buf)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				p.log.Info("peer packet stream closed")
				return
			}
			p.log.Info("peer read error", "err", err)
			return
		}
		if n == 0 {
			continue
		}
		p.rxPackets.Add(1)
		p.room.route(buf[:n], p)
	}
}

// sendRoomMembers sends the room list to the newly joined peer.
func (h *vpnHub) sendRoomMembers(p *vpnPeer) {
	if p.room == nil || p.ctrl == nil {
		return
	}
	peers := p.room.peersSnapshot()
	msg := protocol.RoomMembers{Type: protocol.MsgRoomMembers, Peers: peers}
	if err := protocol.Encode(p.ctrl, msg); err != nil {
		p.log.Warn("send room_members", "err", err)
	}
}

// notifyJoin pushes PeerJoin to every other peer in the room.
func (h *vpnHub) notifyJoin(src *vpnPeer, room *Room) {
	if src.room == nil {
		return
	}
	info := protocol.PeerInfo{
		Pubkey:       src.pubkey,
		EdPubkey:     src.edPubkey,
		IP:           net.IP(src.ip[:]).String(),
		StunEndpoint: src.stunEndpoint,
	}
	msg := protocol.PeerJoin{Type: protocol.MsgPeerJoin, Peer: info}
	room.mu.RLock()
	defer room.mu.RUnlock()
	for _, p := range room.peers {
		if p != src && p.ctrl != nil {
			_ = protocol.Encode(p.ctrl, msg)
		}
	}
}

// notifyLeave pushes PeerLeave to every remaining peer in the room.
func (h *vpnHub) notifyLeave(src *vpnPeer, room *Room) {
	if src.room == nil {
		return
	}
	msg := protocol.PeerLeave{Type: protocol.MsgPeerLeave, IP: net.IP(src.ip[:]).String()}
	room.mu.RLock()
	defer room.mu.RUnlock()
	for _, p := range room.peers {
		if p != src && p.ctrl != nil {
			_ = protocol.Encode(p.ctrl, msg)
		}
	}
}

// allPeers returns all peers across all rooms (for dashboard).
func (h *vpnHub) allPeers() []*vpnPeer {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*vpnPeer, 0)
	for _, r := range h.rooms {
		r.mu.RLock()
		for _, p := range r.peers {
			out = append(out, p)
		}
		r.mu.RUnlock()
	}
	return out
}

// roomsList returns all rooms for the dashboard.
func (h *vpnHub) roomsList() []*Room {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*Room, 0, len(h.rooms))
	for _, r := range h.rooms {
		out = append(out, r)
	}
	return out
}

// gatewayIP returns the first host IP of the room's subnet.
func (r *Room) gatewayIP() [4]byte {
	base := r.subnetBase()
	base[3] = 1
	return base
}

// ensure compilation stubs for unused symbols.
var _ = errors.New
var _ = fmt.Sprintf