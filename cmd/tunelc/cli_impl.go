// cli_impl.go contains the CLI logic shared by both the GUI and no-GUI
// builds. It has NO build tag so it is always compiled in.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"tunel/internal/client"
	"tunel/internal/config"
	"tunel/internal/crypto"
)

// parseTunnelFlag parses a value passed to the repeatable --tunnel flag.
// Accepted formats:
//
//	--tunnel tcp:25565:localhost:25565
//	--tunnel udp:19132:127.0.0.1:19132
//	--tunnel 25565:localhost:25565      # proto defaults to tcp
//
// An optional friendly name can be prefixed with '@':
//
//	--tunnel @mc-java:tcp:25565:localhost:25565
func parseTunnelFlag(s string) (client.TunnelSpec, error) {
	t := client.TunnelSpec{}
	rest := s
	if strings.HasPrefix(rest, "@") {
		idx := strings.Index(rest[1:], ":")
		if idx == -1 {
			return t, errors.New("missing ':' after @name")
		}
		t.Name = rest[1 : 1+idx]
		rest = rest[1+idx+1:]
	}
	parts := strings.SplitN(rest, ":", 3)
	switch len(parts) {
	case 3:
		t.Proto = parts[0]
		if t.Proto == "" {
			t.Proto = "tcp"
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return t, errors.New("invalid public_port: " + parts[1])
		}
		t.PublicPort = port
		t.LocalTarget = parts[2]
	case 2:
		t.Proto = "tcp"
		port, err := strconv.Atoi(parts[0])
		if err != nil {
			return t, errors.New("invalid public_port: " + parts[0])
		}
		t.PublicPort = port
		t.LocalTarget = parts[1]
	default:
		return t, errors.New("expected [proto:]local:remote")
	}
	return t, nil
}

type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func runCLI() error {
	fs := flag.NewFlagSet("tunelc", flag.ExitOnError)
	serverAddr := fs.String("server", "", "host:port of the tunels control endpoint")
	token := fs.String("token", "", "shared secret; must match the server")
	tlsFlag := fs.Bool("tls", false, "enable TLS control channel (requires --cacert or --insecure)")
	cacert := fs.String("cacert", "", "path to PEM-encoded CA cert used to verify the server (only with --tls)")
	insecure := fs.Bool("insecure", false, "skip server cert verification (only with --tls)")
	maxAttempts := fs.Int("max-attempts", 5, "max connect retries (0 = retry forever)")
	vpn := fs.Bool("vpn", false, "VPN mode: open a Layer-3 TUN device and route IP packets via the server's VPN hub")
	stunServer := fs.String("stun-server", "", "STUN server address (empty picks :3478 on the same host as --server)")
	room := fs.String("room", "", "VPN room to join (empty defaults to 'lobby')")
	roomPass := fs.String("room-password", "", "room password (for private rooms)")

	// Single-tunnel shortcuts (kept for backward compat) — they map to --tunnel
	remote := fs.Int("remote", 0, "(legacy) public TCP port; prefer --tunnel")
	local := fs.String("local", "", "(legacy) local host:port; prefer --tunnel")

	tunnelsCSV := stringSlice{}
	fs.Var(&tunnelsCSV, "tunnel", "repeatable: [proto:]public_port:host:port   proto=tcp|udp")
	level := config.RegisterLogLevelFlag(fs, "info")
	_ = fs.Parse(os.Args[1:])

	logger := config.NewLogger(*level, os.Stdout)

	// VPN mode bypasses the tunnel list and goes straight to RunVPN.
	if *vpn {
		// Load or generate identity keypair (persisted in profile).
		profPath := config.DefaultProfilePath()
		prof, _ := config.LoadProfile(profPath)
		if prof.IdentityKey == "" || prof.PrivateKey == "" {
			kp, genErr := crypto.GenerateKeypair()
			if genErr != nil {
				logger.Error("generate keypair", "err", genErr)
				return genErr
			}
			prof.IdentityKey = kp.PublicHex()
			prof.PrivateKey = kp.PrivateHex()
			if svErr := config.SaveProfile(profPath, prof); svErr != nil {
				logger.Warn("save profile with keypair", "err", svErr)
			}
		}
		// Ensure an ed25519 keypair for TLS cert generation.
		if prof.EdPubKey == "" || prof.EdPrivKey == "" {
			epub, epriv, genErr := crypto.GenerateED25519Keypair()
			if genErr != nil {
				logger.Error("generate ed25519", "err", genErr)
				return genErr
			}
			prof.EdPubKey = crypto.EDKeyHex(epub)
			prof.EdPrivKey = crypto.EDKeyHex(epriv)
			if svErr := config.SaveProfile(profPath, prof); svErr != nil {
				logger.Warn("save profile with ed25519", "err", svErr)
			}
			certPEM, keyPEM, certErr := crypto.SelfSignedTLSCert(epriv)
			if certErr != nil {
				logger.Warn("self-signed cert", "err", certErr)
			} else {
				logger.Info("self-signed TLS cert generated", "fingerprint", crypto.HashedKeyFingerprint(epub))
				// certPEM and keyPEM are ready for QUIC listener; they could be
				// cached in a sidecar file next to tunelc.json to avoid re-gen
				// on every start, but for MVP we regenerate each time (ed25519
				// is very cheap in CPU).
				_ = certPEM
				_ = keyPEM
			}
		}

		// Probe STUN endpoint if server was given.
		var endpoint string
		if *stunServer != "" || *serverAddr != "" {
			host := *stunServer
			if host == "" {
				hostPart, _, splitErr := net.SplitHostPort(*serverAddr)
				if splitErr != nil {
					hostPart = "127.0.0.1"
				}
				host = net.JoinHostPort(hostPart, "3478")
			}
			res, probeErr := client.Probe(client.StunConfig{ServerAddr: host, Timeout: 3 * time.Second})
			if probeErr != nil {
				logger.Warn("stun probe failed", "server", host, "err", probeErr)
			} else {
				endpoint = res.Addr.String()
				logger.Info("stun reflexive endpoint", "addr", endpoint)
			}
		}

		cfg := client.Config{
			Server:             *serverAddr,
			Token:              *token,
			TLS:                *tlsFlag,
			CACert:             *cacert,
			Insecure:           *insecure,
			MaxAttempts:        *maxAttempts,
			IdentityPubkeyHex:  prof.IdentityKey,
			IdentityPrivkeyHex: prof.PrivateKey,
			EdPubkeyHex:        prof.EdPubKey,
			EdPrivkeyHex:       prof.EdPrivKey,
			StunServer:         *stunServer,
			StunEndpoint:       endpoint,
			Room:               *room,
			RoomPassword:       *roomPass,
			OnEvent: func(e client.Event) {
				logger.Info(fmt.Sprintf("[vpn %s] %s", e.State, e.Msg))
			},
		}
		if err := maybeFillFromProfileVPN(&cfg); err != nil {
			logger.Warn("profile load failed", "err", err)
		}
		c, err := client.New(cfg, logger)
		if err != nil {
			logger.Error("init client", "err", err)
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		if err := c.RunVPN(ctx); err != nil {
			logger.Error("vpn run", "err", err)
			return err
		}
		return nil
	}

	// Build tunnel list: --tunnel values first, then legacy --remote/--local.
	var specs []client.TunnelSpec
	for _, v := range tunnelsCSV {
		s, err := parseTunnelFlag(v)
		if err != nil {
			logger.Error("invalid --tunnel value", "value", v, "err", err)
			return err
		}
		specs = append(specs, s)
	}
	if *remote != 0 && *local != "" {
		specs = append(specs, client.TunnelSpec{Proto: "tcp", PublicPort: *remote, LocalTarget: *local})
	}

	cfg := client.Config{
		Server:      *serverAddr,
		Token:       *token,
		TLS:         *tlsFlag,
		Tunnels:     specs,
		CACert:      *cacert,
		Insecure:    *insecure,
		MaxAttempts: *maxAttempts,
	}

	// Fill from profile if any field is empty (so users can keep config in
	// tunelc.json and just call `tunelc` with everything defaulted).
	if err := maybeFillFromProfile(&cfg); err != nil {
		logger.Warn("profile load failed", "err", err)
	}

	c, err := client.New(cfg, logger)
	if err != nil {
		logger.Error("init client", "err", err)
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := c.Run(ctx); err != nil {
		logger.Error("client run", "err", err)
		return err
	}
	return nil
}

// maybeFillFromProfileVPN fills empty cfg fields (server/token/cacert/insecure)
// from the persisted profile. Tunnels are ignored in VPN mode.
func maybeFillFromProfileVPN(cfg *client.Config) error {
	path := config.DefaultProfilePath()
	p, err := config.LoadProfile(path)
	if err != nil {
		return err
	}
	if cfg.Server == "" {
		cfg.Server = p.Server
	}
	if cfg.Token == "" {
		cfg.Token = p.Token
	}
	if cfg.CACert == "" {
		cfg.CACert = p.CACert
	}
	if !cfg.Insecure {
		cfg.Insecure = p.Insecure
	}
	return nil
}

// maybeFillFromProfile fills empty cfg fields from the persisted profile JSON
// (tunelc.json) next to the exe. Explicit CLI flags always win.
func maybeFillFromProfile(cfg *client.Config) error {
	path := config.DefaultProfilePath()
	p, err := config.LoadProfile(path)
	if err != nil {
		return err
	}
	if cfg.Server == "" {
		cfg.Server = p.Server
	}
	if cfg.Token == "" {
		cfg.Token = p.Token
	}
	if cfg.CACert == "" {
		cfg.CACert = p.CACert
	}
	if !cfg.Insecure {
		cfg.Insecure = p.Insecure
	}
	if len(cfg.Tunnels) == 0 {
		for _, t := range p.Tunnels {
			cfg.Tunnels = append(cfg.Tunnels, client.TunnelSpec{
				Proto:       t.Proto,
				PublicPort:  t.PublicPort,
				LocalTarget: t.LocalTarget,
				Name:        t.Name,
			})
		}
	}
	return nil
}

// keep unused imports referenced in case future helpers need them.
var _ = strconv.Itoa