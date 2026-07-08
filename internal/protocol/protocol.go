// Package protocol defines the wire format used on the control stream of the
// reverse tunnel. Messages are JSON objects delimited by a single newline
// ('\n').
//
// The recommended way to consume a frame is:
//
//	env, err := protocol.ReadEnvelope(dec)
//	if err != nil { ... }
//	switch env.Type {
//	case protocol.MsgAuth:
//	    var a protocol.Auth
//	    env.Bind(&a)
//	    ...
//	}
package protocol

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// MessageType identifies a control message exchanged between tunelc and tunels.
type MessageType string

const (
	// MsgAuth is sent by the client right after opening the control stream.
	// It carries the shared secret and the tunnel request.
	MsgAuth MessageType = "auth"
	// MsgAuthOK is sent by the server when the tunnel has been granted.
	MsgAuthOK MessageType = "auth_ok"
	// MsgAuthErr is sent by the server when auth fails or the request is denied.
	MsgAuthErr MessageType = "auth_err"
	// MsgPing / MsgPong are keepalive frames exchanged every 30s.
	MsgPing MessageType = "ping"
	MsgPong MessageType = "pong"
	// MsgGoodbye is sent by either side before closing a control stream. It is
	// purely informational; receivers do not need to acknowledge it.
	MsgGoodbye MessageType = "goodbye"

	// VPN P2P signaling messages.
	MsgRoomMembers MessageType = "room_members" // sent by server in response to Auth
	MsgPeerJoin    MessageType = "peer_join"    // sent by server when a new peer enters the VPN room
	MsgPeerLeave   MessageType = "peer_leave"   // sent by server when a peer leaves the room
)

// Auth is the first message sent by the client over the control stream.
// One control stream is opened per tunnel; the SameTls(yamux) session can
// carry several control streams, one per requested tunnel.
type Auth struct {
	Type        MessageType `json:"type"`
	Token       string      `json:"token"`
	PublicPort  int         `json:"public_port"`
	LocalTarget string      `json:"local_target"`
	// Proto is the IP transport the tunnel should use: "tcp", "udp" or "vpn".
	// Empty defaults to "tcp" for backward compatibility with old clients.
	// "vpn" opens a Layer-3 virtual NIC tunnel; PublicPort/LocalTarget are
	// ignored by the server in that mode.
	Proto string `json:"proto,omitempty"`
	// VPNSubnetHint, only used when Proto=="vpn", is the suggested subnet
	// (CIDR) the client would like to be part of. The server may ignore it
	// and assign its own IP; the assigned IP comes back in AuthOK.VPNIP.
	VPNSubnetHint string `json:"vpn_subnet_hint,omitempty"`

	// IdentityPubkey is the hex-encoded curve25519 public key of this tunelc
	// instance. Sent only when Proto=="vpn". The server uses it to
	// authenticate QUIC P2P connections between peers sharing the same room.
	IdentityPubkey string `json:"identity_pubkey,omitempty"`
	// EdPubkey is the hex-encoded ed25519 public key, used by peers to
	// validate each other's TLS certificates during QUIC handshake.
	EdPubkey string `json:"ed_pubkey,omitempty"`
	// StunEndpoint is the public UDP endpoint discovered by the client via
	// STUN (e.g. "1.2.3.4:51234"). It is only meaningful with Proto=="vpn".
	StunEndpoint string `json:"stun_endpoint,omitempty"`
	// Room is the human-readable room name the peer wants to join (e.g.
	// "lobby", "cs-1.6", "mc-casa"). Defaults to "lobby" when empty.
	Room string `json:"room,omitempty"`
	// RoomPassword authenticates entry to private rooms. Ignored for public rooms.
	RoomPassword string `json:"room_password,omitempty"`
}

// AuthOK acknowledges a granted tunnel. The TunnelID is a 16-bit number the
// server writes at the start of every data stream it opens for this tunnel;
// the client uses it to demultiplex data streams across tunnels.
//
// For VPN tunnels, TunnelID is also used as the trailing 16 bits of the
// assigned IPv4 inside the server's VPN subnet (e.g. TunnelID=1 ->
// 10.99.0.1). VPNIP is the fully-formatted assigned IPv4 in dotted quad
// form; the client uses it to configure its TUN device.
type AuthOK struct {
	Type      MessageType `json:"type"`
	SessionID string      `json:"session_id"`
	TunnelID  uint16      `json:"tunnel_id"`
	// VPNIP is set only when Proto=="vpn": the assigned IPv4 address the
	// client should configure on its TUN interface (e.g. "10.99.0.2").
	VPNIP    string `json:"vpn_ip,omitempty"`
	// VPNMask is the dotted-quad subnet mask of the VPN (e.g. "255.255.255.0").
	VPNMask string `json:"vpn_mask,omitempty"`
	// VPNGateway is the IP the client should use as gateway of last resort,
	// if it wants to channel all traffic through the tunnel. May be empty.
	VPNGateway string `json:"vpn_gateway,omitempty"`
	// VPNSubnet is the CIDR form of the whole VPN subnet (e.g. "10.99.0.0/24")
	// for display/observability purposes.
	VPNSubnet string `json:"vpn_subnet,omitempty"`
	// Room is the name of the room the peer joined (confirmed by server).
	Room string `json:"room,omitempty"`
	// RoomSize reports the current number of peers in the room.
	RoomSize int `json:"room_size,omitempty"`
}

// AuthErr reports a denied tunnel. Reason is human-readable.
type AuthErr struct {
	Type   MessageType `json:"type"`
	Reason string      `json:"reason"`
}

// Ping is a keepalive frame. No payload beyond the type.
type Ping struct {
	Type MessageType `json:"type"`
}

// Pong is the keepalive reply.
type Pong struct {
	Type MessageType `json:"type"`
}

// PeerInfo describes one connected VPN peer. Sent by the server to all
// room members for P2P connection attempts.
type PeerInfo struct {
	Pubkey       string `json:"pubkey"`        // hex curve25519 public key
	EdPubkey     string `json:"ed_pubkey"`     // hex ed25519 public key (for cert verification)
	IP           string `json:"ip"`            // assigned VPN IP (dotted quad)
	StunEndpoint string `json:"stun_endpoint"` // public UDP host:port from STUN
}

// RoomMembers is sent by the server on a control stream right after AuthOK
// when the peer enters a VPN room. It lists every other peer currently in the
// same room so the client may attempt P2P connections.
type RoomMembers struct {
	Type  MessageType `json:"type"`
	Peers []PeerInfo  `json:"peers"`
}

// PeerJoin is a push notification sent by the server to every other peer in
// the room when a new peer arrives (after AuthOK).
type PeerJoin struct {
	Type MessageType `json:"type"`
	Peer PeerInfo    `json:"peer"`
}

// PeerLeave is a push notification sent by the server to every other peer
// when someone leaves the room (or the control stream is lost).
type PeerLeave struct {
	Type MessageType `json:"type"`
	IP   string      `json:"ip"` // VPN IP of the departed peer
}

// Envelope wraps a single control frame. Payload holds the raw JSON of the
// message body; callers funneled it into a concrete struct with Bind.
type Envelope struct {
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"-"` // populated by ReadEnvelope, not on the wire
}

// Bind unmarshals the captured payload into v. v must be a pointer.
func (e *Envelope) Bind(v any) error {
	if len(e.Payload) == 0 {
		return nil
	}
	return json.Unmarshal(e.Payload, v)
}

// Decoder reads line-delimited JSON control messages from r.
type Decoder struct {
	r *bufio.Reader
}

// NewDecoder returns a Decoder that reads from r.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: bufio.NewReader(r)}
}

// ReadEnvelope reads the next control frame. The Type field is set and the
// raw line (including the type) is stored in Payload so Bind can fully decode
// it. Returns io.EOF when the underlying reader is closed cleanly.
func (d *Decoder) ReadEnvelope() (*Envelope, error) {
	line, err := d.r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	// Trim trailing newline; ReadBytes keeps it.
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
	}
	// We need Type separately. Parse twice: once for the header to learn the
	// type, the full line is retained as Payload for Bind.
	var hdr struct {
		Type MessageType `json:"type"`
	}
	if err := json.Unmarshal(line, &hdr); err != nil {
		return nil, fmt.Errorf("protocol decode header: %w", err)
	}
	return &Envelope{
		Type:    hdr.Type,
		Payload: json.RawMessage(line),
	}, nil
}

// Encode writes msg as a single JSON line followed by '\n' to w.
func Encode(w io.Writer, msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("protocol encode: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	_, err = w.Write([]byte{'\n'})
	return err
}