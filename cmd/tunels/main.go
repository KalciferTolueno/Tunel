// Command tunels is the server side of the reverse tunnel. Run it on a host
// with a public IP (your VPS).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"tunel/internal/config"
	"tunel/internal/server"
)

func main() {
	fs := flag.NewFlagSet("tunels", flag.ExitOnError)
	bind := fs.String("bind", ":9000", "control listener address")
	token := fs.String("token", "", "shared secret (required)")
	tlsFlag := fs.Bool("tls", false, "enable TLS control channel (requires --cert and --key)")
	cert := fs.String("cert", "server.crt", "TLS cert PEM (only with --tls)")
	key := fs.String("key", "server.key", "TLS key PEM (only with --tls)")
	allowedPorts := fs.String("allowed-ports", "", "comma-separated whitelist of public ports a client may request (empty = any)")
	vpn := fs.Bool("vpn", false, "enable Layer-3 VPN mode: hub routes IP packets between connected tunelc --vpn peers (10.99.0.0/24)")
	vpnSubnet := fs.String("vpn-subnet", "10.99.0.0/24", "VPN subnet (when --vpn)")
	stunBind := fs.String("stun-bind", "", "UDP address for the embedded STUN server (e.g. \":3478\" or \"0.0.0.0:3478\"). Empty disables.")
	dashboardBind := fs.String("dashboard-bind", "", "HTTP dashboard bind (e.g. \":9001\"). Empty disables.")
	level := config.RegisterLogLevelFlag(fs, "info")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	logger := config.NewLogger(*level, os.Stdout)

	if *token == "" {
		logger.Error("--token is required")
		os.Exit(2)
	}

	cfg := server.Config{
		Bind:         *bind,
		Token:        *token,
		CertFile:     *cert,
		KeyFile:      *key,
		AllowedPorts: config.ParseAllowedPorts(*allowedPorts),
		TLS:          *tlsFlag,
		VPNEnabled:   *vpn,
		VPNSubnet:    *vpnSubnet,
	}

	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Error("init server", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Launch STUN server if requested.
	if *stunBind != "" {
		go func() {
			if serr := server.RunSTUN(ctx, server.STUNConfig{Bind: *stunBind}, logger); serr != nil {
				logger.Error("stun server", "err", serr)
			}
		}()
	}

	// Dashboard.
	if *dashboardBind != "" {
		go func() {
			if derr := server.RunDashboard(server.DashboardConfig{Bind: *dashboardBind}, srv); derr != nil {
				logger.Error("dashboard", "err", derr)
			}
		}()
	}

	if err := srv.Run(ctx); err != nil {
		logger.Error("server run", "err", err)
		os.Exit(1)
	}
	fmt.Println()
}