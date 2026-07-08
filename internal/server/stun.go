package server

import (
	"context"
	"log/slog"
	"net"

	"github.com/pion/stun"
)

// STUNConfig holds the start-up parameters of the embedded STUN server.
type STUNConfig struct {
	Bind string // e.g. ":3478" or "0.0.0.0:3478"
}

// RunSTUN starts a blocking STUN server goroutine that responds to binding
// requests until ctx is cancelled.
func RunSTUN(ctx context.Context, cfg STUNConfig, logger *slog.Logger) error {
	addr, err := net.ResolveUDPAddr("udp", cfg.Bind)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	logger.Info("stun server listening", "bind", cfg.Bind)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 2048)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !stun.IsMessage(buf[:n]) {
			continue
		}
		m := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if err := m.Decode(); err != nil {
			continue
		}
		if m.Type.Class != stun.ClassRequest || m.Type.Method != stun.MethodBinding {
			continue
		}
		resp, marshalErr := stun.Build(
			stun.NewType(stun.MethodBinding, stun.ClassSuccessResponse),
			stun.NewTransactionIDSetter(m.TransactionID),
			&stun.XORMappedAddress{IP: remote.IP, Port: remote.Port},
			stun.Fingerprint,
		)
		if marshalErr != nil {
			continue
		}
		if _, wErr := conn.WriteTo(resp.Raw, remote); wErr != nil {
			logger.Debug("stun write", "err", wErr)
		}
	}
}