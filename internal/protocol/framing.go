// framing.go defines the on-stream byte framing used by data streams.
//
// Every data stream opened by the server carries a 2-byte big-endian TunnelID
// header at its very start. After that header:
//
//   - For TCP tunnels: the rest of the stream is raw bytes (io.Copy). No
//     additional framing is needed because a TCP connection is a reliable byte
//     stream and yamux preserves that property end-to-end.
//
//   - For UDP tunnels: the rest of the stream is a sequence of frames. Each
//     frame has a 1-byte Type, an optional payload, and uses a length prefix
//     for variable parts:
//
//       Type 0x00  HELLO        : [1 byte: addr-len][addr bytes]
//                                 Sent once as the first frame to inform the
//                                 client of the public peer's address for
//                                 logging / state. The client can also use it
//                                 to associate a local UDP socket.
//       Type 0x01  DATAGRAM     : [2 bytes BE: data-len][data bytes]
//                                 One UDP datagram flowing public peer ->
//                                 local target, or the reverse direction.
//       Type 0x02  GOODBYE       : no payload. Sent by either side to signal
//                                 that the peer has gone (timeout); the
//                                 stream should be closed.
//
// The HELLO frame is only sent server -> client. The other direction is pure
// DATAGRAM frames since the local UDP socket already knows where to send
// responses.
package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// TunnelIDLen is the byte size of the tunnel ID header on data streams.
const TunnelIDLen = 2

// Frame types on UDP data streams.
const (
	FrameHello   byte = 0x00
	FrameDatagram byte = 0x01
	FrameGoodbye byte = 0x02
)

// MaxDatagramLen is the maximum UDP payload we can frame. UDP MTU is at most
// 65507 bytes for IPv4; we use 65535 which fits a uint16 length prefix.
const MaxDatagramLen = 65535

// WriteTunnelID writes the 2-byte big-endian tunnel id header to w.
func WriteTunnelID(w io.Writer, id uint16) error {
	var buf [TunnelIDLen]byte
	binary.BigEndian.PutUint16(buf[:], id)
	_, err := w.Write(buf[:])
	return err
}

// ReadTunnelID reads the 2-byte big-endian tunnel id header from r.
func ReadTunnelID(r io.Reader) (uint16, error) {
	var buf [TunnelIDLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

// WriteHelloFrame writes a HELLO frame carrying the peer's address (string).
func WriteHelloFrame(w io.Writer, peer string) error {
	if len(peer) > 255 {
		return fmt.Errorf("protocol: hello addr too long (%d)", len(peer))
	}
	hdr := []byte{FrameHello, byte(len(peer))}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(peer) > 0 {
		if _, err := io.WriteString(w, peer); err != nil {
			return err
		}
	}
	return nil
}

// ReadHelloFrame reads a HELLO frame and returns the peer address string.
func ReadHelloFrame(r io.Reader) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != FrameHello {
		return "", fmt.Errorf("protocol: expected HELLO frame, got 0x%02x", hdr[0])
	}
	addr := make([]byte, hdr[1])
	if _, err := io.ReadFull(r, addr); err != nil {
		return "", err
	}
	return string(addr), nil
}

// WriteDatagramFrame writes a DATAGRAM frame carrying one UDP packet.
func WriteDatagramFrame(w io.Writer, data []byte) error {
	if len(data) > MaxDatagramLen {
		return fmt.Errorf("protocol: datagram too long (%d)", len(data))
	}
	var hdr [3]byte
	hdr[0] = FrameDatagram
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame reads any UDP frame and returns its type and payload (for
// DATAGRAM) or address (for HELLO). GOODBYE returns a nil payload.
// Caller passes a reusable buffer to avoid allocations on the hot path.
func ReadFrame(r io.Reader, buf []byte) (frameType byte, payload []byte, peer string, err error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:1]); err != nil {
		return 0, nil, "", err
	}
	switch hdr[0] {
	case FrameHello:
		if _, err := io.ReadFull(r, hdr[1:2]); err != nil {
			return 0, nil, "", err
		}
		peerBuf := make([]byte, hdr[1])
		if _, err := io.ReadFull(r, peerBuf); err != nil {
			return 0, nil, "", err
		}
		return FrameHello, nil, string(peerBuf), nil
	case FrameDatagram:
		if _, err := io.ReadFull(r, hdr[1:3]); err != nil {
			return 0, nil, "", err
		}
		n := int(binary.BigEndian.Uint16(hdr[1:3]))
		if n > MaxDatagramLen {
			return 0, nil, "", fmt.Errorf("protocol: datagram len %d exceeds max", n)
		}
		if cap(buf) < n {
			buf = make([]byte, n)
		} else {
			buf = buf[:n]
		}
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, nil, "", err
		}
		return FrameDatagram, buf, "", nil
	case FrameGoodbye:
		return FrameGoodbye, nil, "", nil
	default:
		return 0, nil, "", fmt.Errorf("protocol: unknown frame type 0x%02x", hdr[0])
	}
}

// MustUDPAddr is a small convenience used by server code to format a peer
// address for logging without nil checks.
func MustUDPAddr(a *net.UDPAddr) string {
	if a == nil {
		return ""
	}
	return a.String()
}