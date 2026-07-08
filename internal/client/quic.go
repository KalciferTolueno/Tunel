//go:build vpn

// quic.go implements P2P transport via quic-go.

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type p2pManager struct {
	logger    *slog.Logger
	listener  *quic.Listener
	tlsCert   []tls.Certificate
	myVPNIP   string
	tunWrite  func(pkt []byte) error // callback to inject received data into TUN
	connMu    sync.Mutex
	conns     map[string]*p2pConn
	stopCh    chan struct{}
	closeOnce sync.Once
	peerDb    func(ip string) (fingerprint string, found bool)
	listAll   func() []string
}

type p2pConn struct {
	peerIP   string
	qConn    *quic.Conn
	stream   io.ReadWriteCloser
	lastSeen time.Time
}

func newP2PManager(log *slog.Logger, peerDb func(string) (string, bool), listAll func() []string, tunWrite func([]byte) error) *p2pManager {
	return &p2pManager{
		logger:   log.With("component", "p2p"),
		conns:    make(map[string]*p2pConn),
		peerDb:   peerDb,
		listAll:  listAll,
		tunWrite: tunWrite,
		stopCh:   make(chan struct{}),
	}
}

func (m *p2pManager) Start(certPEM, keyPEM []byte, myVPNIP string) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("p2p: load cert: %w", err)
	}
	if len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	var fp string
	if cert.Leaf != nil {
		if pub, ok := cert.Leaf.PublicKey.(ed25519.PublicKey); ok {
			fp = shortFP(pub)
		}
	}
	m.tlsCert = []tls.Certificate{cert}
	m.myVPNIP = myVPNIP

	tlsConf := &tls.Config{
		Certificates: m.tlsCert,
		MinVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			return m.verifyIncoming(raw)
		},
	}
	ln, err := quic.ListenAddr("0.0.0.0:0", tlsConf, quicCfg())
	if err != nil {
		return fmt.Errorf("p2p listen: %w", err)
	}
	m.listener = ln
	m.logger.Info("p2p listener ready", "fp", fp, "addr", ln.Addr().String())
	go m.acceptLoop()
	go m.reapLoop()
	return nil
}

func (m *p2pManager) Stop() {
	m.closeOnce.Do(func() {
		close(m.stopCh)
		if m.listener != nil {
			_ = m.listener.Close()
		}
		m.connMu.Lock()
		defer m.connMu.Unlock()
		for _, c := range m.conns {
			_ = c.stream.Close()
			_ = c.qConn.CloseWithError(0, "shutdown")
		}
	})
}

func (m *p2pManager) Dial(peerIP, endpoint string) error {
	fp, found := m.peerDb(peerIP)
	if !found {
		return fmt.Errorf("p2p dial %s: not registered", peerIP)
	}
	tlsConf := &tls.Config{
		Certificates:       m.tlsCert,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			return verifyFingerprint(raw, fp)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q, err := quic.DialAddr(ctx, endpoint, tlsConf, quicCfg())
	if err != nil {
		return fmt.Errorf("p2p dial %s: %w", peerIP, err)
	}
	s, err := q.OpenStreamSync(ctx)
	if err != nil {
		_ = q.CloseWithError(0, "stream")
		return fmt.Errorf("p2p stream: %w", err)
	}
	if err := writeHello(s, peerIP, m.myVPNIP); err != nil {
		_ = s.Close()
		_ = q.CloseWithError(0, "hello")
		return fmt.Errorf("p2p hello: %w", err)
	}
	m.register(peerIP, q, s)
	m.logger.Info("p2p connected", "peer", peerIP)
	// Pump incoming data back to TUN.
	go m.pumpIncoming(peerIP, s)
	return nil
}

func (m *p2pManager) Route(dstIP string, pkt []byte) bool {
	m.connMu.Lock()
	pc, ok := m.conns[dstIP]
	m.connMu.Unlock()
	if !ok || pc == nil || pc.stream == nil {
		return false
	}
	if err := writeFrame(pc.stream, pkt); err != nil {
		m.logger.Debug("p2p write fail", "peer", dstIP, "err", err)
		m.evict(dstIP)
		return false
	}
	pc.lastSeen = time.Now()
	return true
}

// --- internal ---

func (m *p2pManager) acceptLoop() {
	for {
		q, err := m.listener.Accept(context.Background())
		if err != nil {
			return
		}
		go m.handleIncoming(q)
	}
}

func (m *p2pManager) handleIncoming(q *quic.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := q.AcceptStream(ctx)
	if err != nil {
		_ = q.CloseWithError(1, "no stream")
		return
	}
	peerIP, _, err := readHello(s)
	if err != nil {
		_ = s.Close()
		_ = q.CloseWithError(1, "bad hello")
		return
	}
	_ = writeHello(s, peerIP, m.myVPNIP)
	m.register(peerIP, q, s)
	m.logger.Info("p2p accepted", "peer", peerIP)

	// Pump: read frames from this peer's QUIC stream and feed them to TUN.
	go m.pumpIncoming(peerIP, s)
}

// pumpIncoming reads framed IP packets from a P2P stream and injects them
// into the TUN device via the configured tunWrite callback.
func (m *p2pManager) pumpIncoming(peerIP string, r io.Reader) {
	buf := make([]byte, 65535)
	for {
		n, err := readFrame(r, buf)
		if err != nil {
			return
		}
		if m.tunWrite != nil {
			_ = m.tunWrite(buf[:n])
		}
		_ = peerIP
	}
}

func (m *p2pManager) verifyIncoming(rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("p2p: no cert")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("p2p: cert parse: %w", err)
	}
	fp := fpFromCert(cert)
	if fp == "" {
		return errors.New("p2p: no ed25519 key")
	}
	for _, ip := range m.listAll() {
		if pfp, ok := m.peerDb(ip); ok && pfp == fp {
			return nil
		}
	}
	return fmt.Errorf("p2p: unknown fingerprint %s", fp)
}

func (m *p2pManager) register(ip string, q *quic.Conn, s *quic.Stream) {
	m.connMu.Lock()
	if old, ok := m.conns[ip]; ok {
		_ = old.stream.Close()
		_ = old.qConn.CloseWithError(0, "replaced")
	}
	m.conns[ip] = &p2pConn{peerIP: ip, qConn: q, stream: s, lastSeen: time.Now()}
	m.connMu.Unlock()
}

func (m *p2pManager) evict(ip string) {
	m.connMu.Lock()
	if pc, ok := m.conns[ip]; ok {
		_ = pc.stream.Close()
		_ = pc.qConn.CloseWithError(0, "evicted")
		delete(m.conns, ip)
	}
	m.connMu.Unlock()
}

// ActiveCount returns the number of currently active P2P QUIC connections.
func (m *p2pManager) ActiveCount() int {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	return len(m.conns)
}

// --- wire helpers ---

func writeHello(w io.Writer, peerIP, myIP string) error {
	hdr := []byte{byte(len(peerIP)), byte(len(myIP))}
	data := append(append(hdr, []byte(peerIP)...), []byte(myIP)...)
	return writeFrame(w, data)
}

func readHello(r io.Reader) (peerIP, myIP string, err error) {
	var buf [512]byte
	n, err := readFrame(r, buf[:])
	if err != nil {
		return "", "", err
	}
	if n < 2 {
		return "", "", errors.New("p2p: hello too short")
	}
	alen := int(buf[0])
	blen := int(buf[1])
	if alen+blen+2 != n {
		return "", "", fmt.Errorf("p2p: hello mismatch")
	}
	peerIP = string(buf[2 : 2+alen])
	if blen > 0 {
		myIP = string(buf[2+alen : 2+alen+blen])
	}
	return peerIP, myIP, nil
}

func readFrame(r io.Reader, buf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n > len(buf) || n == 0 {
		return 0, io.EOF
	}
	return io.ReadFull(r, buf[:n])
}

func writeFrame(w io.Writer, data []byte) error {
	h := []byte{byte(len(data) >> 8), byte(len(data) & 0xFF)}
	_, err := w.Write(append(h, data...))
	return err
}

func verifyFingerprint(rawCerts [][]byte, expected string) error {
	if len(rawCerts) == 0 {
		return errors.New("p2p: no cert")
	}
	c, _ := x509.ParseCertificate(rawCerts[0])
	if c == nil {
		return errors.New("p2p: bad cert")
	}
	if fpFromCert(c) != expected {
		return errors.New("p2p: fp mismatch")
	}
	return nil
}

func fpFromCert(cert *x509.Certificate) string {
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return shortFP(pub)
}

func shortFP(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:4])
}

// shortFPFromHex parses a hex ed25519 public key and returns its fingerprint.
func shortFPFromHex(pubHex string) string {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ""
	}
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:4])
}

func quicCfg() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:          30 * time.Second,
		KeepAlivePeriod:         15 * time.Second,
		MaxIncomingStreams:      100,
		MaxIncomingUniStreams:   20,
		InitialPacketSize:       1200,
		DisablePathMTUDiscovery: false,
	}
}

// reapLoop evicts P2P connections idle for >90s.
func (m *p2pManager) reapLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-t.C:
			now := time.Now()
			m.connMu.Lock()
			for ip, pc := range m.conns {
				if now.Sub(pc.lastSeen) > 90*time.Second {
					m.logger.Debug("reap idle p2p", "peer", ip)
					_ = pc.stream.Close()
					_ = pc.qConn.CloseWithError(0, "reap")
					delete(m.conns, ip)
				}
			}
			m.connMu.Unlock()
		}
	}
}

var _ = io.EOF