// room.go holds the per-room state: subnet, peers, and allocation.

package server

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"tunel/internal/protocol"
)

// Room represents one isolated VPN room (e.g. "lobby", "cs-1.6", "mc-casa").
// Each room gets its own /24 subnet and isolates broadcasts and unicast
// from other rooms.
type Room struct {
	Name      string
	Subnet    *net.IPNet
	Private   bool
	Password  string
	mu        sync.RWMutex
	peers     map[[4]byte]*vpnPeer
	byConn    map[*Connection]*vpnPeer
	nextIP    byte

	// Stats
	peerCount atomic.Int64
}

// newRoom creates a room with the given subnet (must be /24).
func newRoom(name string, subnet *net.IPNet, private bool, password string) (*Room, error) {
	if subnet == nil || subnet.IP.To4() == nil {
		return nil, errors.New("room needs IPv4 /24 subnet")
	}
	r := &Room{
		Name:     name,
		Subnet:   subnet,
		Private:  private,
		Password: password,
		peers:    make(map[[4]byte]*vpnPeer),
		byConn:   make(map[*Connection]*vpnPeer),
		nextIP:   1,
	}
	return r, nil
}

// subnetBase returns the base (network address) of this room's subnet.
func (r *Room) subnetBase() [4]byte {
	var b [4]byte
	copy(b[:], r.Subnet.IP.To4())
	return b
}

// maskDotted returns the subnet mask in dotted-quad form.
func (r *Room) maskDotted() string {
	return net.IP(r.Subnet.Mask).String()
}

// cidr returns the subnet CIDR string.
func (r *Room) cidr() string {
	return r.Subnet.String()
}

// allocate returns the next free IP inside the room's subnet.
func (r *Room) allocate() ([4]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	base := r.Subnet.IP.To4()
	for i := 0; i < 254; i++ {
		oct := r.nextIP
		r.nextIP++
		if r.nextIP >= 255 {
			r.nextIP = 1
		}
		if oct == 0 || oct == 255 {
			continue
		}
		var candidate [4]byte
		copy(candidate[:], base)
		candidate[3] = oct
		if _, taken := r.peers[candidate]; taken {
			continue
		}
		return candidate, nil
	}
	return [4]byte{}, errors.New("room full")
}

// grantPeer adds a peer to this room.
func (r *Room) grantPeer(conn *Connection, pubkey, edPubkey, endpoint string) (*vpnPeer, error) {
	ip, err := r.allocate()
	if err != nil {
		return nil, err
	}
	p := newVPNPeer(r, ip, conn, pubkey, edPubkey, endpoint)
	r.mu.Lock()
	r.peers[ip] = p
	r.byConn[conn] = p
	r.mu.Unlock()
	r.peerCount.Store(int64(len(r.peers)))
	return p, nil
}

func newVPNPeer(room *Room, ip [4]byte, conn *Connection, pubkey, edPubkey, endpoint string) *vpnPeer {
	return &vpnPeer{
		room:         room,
		ip:           ip,
		str:          net.IP(ip[:]),
		conn:         conn,
		pubkey:       pubkey,
		edPubkey:     edPubkey,
		stunEndpoint: endpoint,
	}
}

// releasePeer removes a peer and returns true if it was found.
func (r *Room) releasePeer(conn *Connection) *vpnPeer {
	r.mu.Lock()
	p, ok := r.byConn[conn]
	if !ok {
		r.mu.Unlock()
		return nil
	}
	delete(r.peers, p.ip)
	delete(r.byConn, conn)
	r.mu.Unlock()
	r.peerCount.Store(int64(len(r.peers)))
	p.cleanup()
	return p
}

// lookupIP returns the peer with the given room-local IP.
func (r *Room) lookupIP(ip [4]byte) *vpnPeer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.peers[ip]
}

// peersSnapshot returns a slice of all peer IPs in the room.
func (r *Room) peersSnapshot() []protocol.PeerInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]protocol.PeerInfo, 0, len(r.peers))
	for _, p := range r.peers {
		out = append(out, protocol.PeerInfo{
			Pubkey:       p.pubkey,
			EdPubkey:     p.edPubkey,
			IP:           net.IP(p.ip[:]).String(),
			StunEndpoint: p.stunEndpoint,
		})
	}
	return out
}

// broadcast sends a packet to every other peer in the room.
func (r *Room) broadcast(pkt []byte, from *vpnPeer) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.peers {
		if p == from || p.pkts == nil {
			continue
		}
		if err := protocol.WritePacket(p.pkts, pkt); err != nil {
			continue
		}
		p.txPackets.Add(1)
	}
}

// route sends a packet to the destination peer, if found.
func (r *Room) route(pkt []byte, from *vpnPeer) {
	dst, ok := protocol.IPv4Dst(pkt)
	if !ok {
		return
	}
	if protocol.IsBroadcast(dst) {
		r.broadcast(pkt, from)
		return
	}
	target := r.lookupIP(dst)
	if target == nil || target == from || target.pkts == nil {
		return
	}
	if err := protocol.WritePacket(target.pkts, pkt); err != nil {
		return
	}
	target.txPackets.Add(1)
}

// size returns the current number of peers in this room.
func (r *Room) size() int {
	return int(r.peerCount.Load())
}