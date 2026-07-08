// vpn.go defines the wire framing for IP packets carried over yamux streams
// in VPN tunnel mode.
//
// After the AuthOK control handshake, the client opens exactly one dedicated
// "packet stream" via yamux.Open() and signals it by writing a 1-byte magic
// header:
//
//	[1 byte: packetStreamMagic = 0x9A]
//
// From that point onwards the stream is a sequence of length-prefixed frames:
//
//	[2 bytes BE: length N][N bytes: raw IP packet]
//
// The server reads IP packets, peeks at the destination IPv4 address from
// the packet header (bytes 16-19), and either forwards to the peer owning
// that IP or replicates the packet to every other peer when the destination
// is a broadcast (255.255.255.255 or the subnet broadcast x.x.x.255).
//
// IPv6 is supported as long as the destination address falls inside the
// delegated prefix; the lookup simply treats IPv6 destination bytes (24-39)
// as a 16-byte key. For the MVP the VPN only carries IPv4.
package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

// PacketStreamMagic is written by the client right after opening the packet
// stream so the server can validate it's a VPN packet stream and not a
// random data stream from another tunnel type.
const PacketStreamMagic byte = 0x9A

// MaxPacketLen is the largest IP packet we transport. 65535 is the IPv4
// theoretical max; in practice path MTU is much smaller but TUN devices
// commonly accept up to 65535 for fragmented ingress.
const MaxPacketLen = 65535

// WritePacketStreamMagic writes the 1-byte header that identifies a VPN
// packet stream.
func WritePacketStreamMagic(w io.Writer) error {
	_, err := w.Write([]byte{PacketStreamMagic})
	return err
}

// ReadPacketStreamMagic reads and validates the 1-byte header.
func ReadPacketStreamMagic(r io.Reader) error {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	if buf[0] != PacketStreamMagic {
		return errors.New("protocol: not a vpn packet stream (bad magic)")
	}
	return nil
}

// WritePacket writes one IP packet with a 2-byte big-endian length prefix.
func WritePacket(w io.Writer, pkt []byte) error {
	if len(pkt) > MaxPacketLen {
		return errors.New("protocol: packet too long")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(pkt)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(pkt) == 0 {
		return nil
	}
	_, err := w.Write(pkt)
	return err
}

// ReadPacket reads one length-prefixed IP packet into dst, returning the
// number of bytes used. dst must have capacity for at least MaxPacketLen
// bytes.
func ReadPacket(r io.Reader, dst []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return 0, nil
	}
	if n > MaxPacketLen || n > cap(dst) {
		return 0, errors.New("protocol: packet length exceeds buffer")
	}
	if _, err := io.ReadFull(r, dst[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

// IPv4Dst returns the destination IPv4 address extracted from the packet
// header (bytes 16-19). If the packet is not an IPv4 packet, returns
// (0, false).
func IPv4Dst(pkt []byte) ([4]byte, bool) {
	if len(pkt) < 20 {
		return [4]byte{}, false
	}
	if pkt[0]>>4 != 4 { // first nibble = IP version
		return [4]byte{}, false
	}
	var dst [4]byte
	copy(dst[:], pkt[16:20])
	return dst, true
}

// IPv4Src returns the source IPv4 address extracted from the packet header.
func IPv4Src(pkt []byte) ([4]byte, bool) {
	if len(pkt) < 20 {
		return [4]byte{}, false
	}
	if pkt[0]>>4 != 4 {
		return [4]byte{}, false
	}
	var src [4]byte
	copy(src[:], pkt[12:16])
	return src, true
}

// IsBroadcast reports whether dst is the limited broadcast (255.255.255.255)
// or a subnet-directed broadcast (last octet 255 — assumes /24 VPN).
func IsBroadcast(dst [4]byte) bool {
	return dst == [4]byte{255, 255, 255, 255} || dst[3] == 255
}