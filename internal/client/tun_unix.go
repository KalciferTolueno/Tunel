//go:build vpn && (linux || darwin)

// tun_unix.go opens and configures a TUN device on Linux (/dev/net/tun) and
// macOS (utunN) using golang.zx2c4.com/wireguard/tun. Configuration is done
// with `ip` (Linux) or `ifconfig` (macOS). Both require root (sudo tunelc).

package client

import (
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"tunel/internal/protocol"
)

const tunAdapterName = "tunelvpn"

type wgTUN struct {
	d tun.Device
}

func (w *wgTUN) Name() (string, error) { return w.d.Name() }

func (w *wgTUN) Read(buf []byte, off int) (int, error) { return w.d.Read(buf, off) }

func (w *wgTUN) Write(buf []byte, off int) (int, error) { return w.d.Write(buf, off) }

func (w *wgTUN) Close() error { return w.d.Close() }

func (w *wgTUN) Events() <-chan TunEvent {
	out := make(chan TunEvent, 1)
	go func() {
		for ev := range w.d.Events() {
			if ev&tun.EventUp != 0 {
				out <- TunEventUp
			}
			if ev&tun.EventDown != 0 {
				out <- TunEventDown
			}
		}
		close(out)
	}()
	return out
}

func (w *wgTUN) MTU() (int, error) { return w.d.MTU() }

func openTUN(ok protocol.AuthOK) (TUNDevice, error) {
	dev, err := tun.CreateTUN(tunAdapterName, 1400)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w (run as root?)", err)
	}
	return &wgTUN{d: dev}, nil
}

func configureTUN(dev TUNDevice, ok protocol.AuthOK) error {
	name, err := dev.Name()
	if err != nil {
		return fmt.Errorf("get tun name: %w", err)
	}
	mtu := "1400"
	if runtime.GOOS == "darwin" {
		// macOS utun can't take a static IP via `ip`; it requires ifconfig.
		c := fmt.Sprintf("ifconfig %s %s %s up", name, ok.VPNIP, ok.VPNGateway)
		out, err := exec.Command("sh", "-c", c).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ifconfig: %w: %s", err, out)
		}
		if ok.VPNSubnet != "" {
			rr := fmt.Sprintf("route -n add -net %s %s", ok.VPNSubnet, name)
			_, _ = exec.Command("sh", "-c", rr).CombinedOutput()
		}
		rr2 := fmt.Sprintf("ifconfig %s mtu %s", name, mtu)
		_, _ = exec.Command("sh", "-c", rr2).CombinedOutput()
		return nil
	}

	// Linux
	cmds := []string{
		fmt.Sprintf("ip link set %s up", name),
		fmt.Sprintf("ip addr add %s/%s dev %s", ok.VPNIP, maskToPrefix(ok.VPNMask), name),
		fmt.Sprintf("ip link set %s mtu %s", name, mtu),
	}
	for _, c := range cmds {
		out, err := exec.Command("sh", "-c", c).CombinedOutput()
		if err != nil {
			return fmt.Errorf("cmd %q: %w: %s", c, err, out)
		}
	}
	return nil
}

// keep unused import referenced in case it's not used anymore on some builds.
var _ = unix.Close
var _ = time.Second

// maskToPrefix turns a dotted-quad mask (255.255.255.0) into a "/24" prefix
// length for `ip addr add` on Linux. We support only a subset of contiguous
// masks because that's all anyone uses here; falls back to /32 if unknown.
func maskToPrefix(mask string) string {
	switch mask {
	case "255.255.255.255":
		return "32"
	case "255.255.255.254":
		return "31"
	case "255.255.255.252":
		return "30"
	case "255.255.255.248":
		return "29"
	case "255.255.255.240":
		return "28"
	case "255.255.255.224":
		return "27"
	case "255.255.255.192":
		return "26"
	case "255.255.255.128":
		return "25"
	case "255.255.255.0":
		return "24"
	case "255.255.254.0":
		return "23"
	case "255.255.252.0":
		return "22"
	case "255.255.0.0":
		return "16"
	default:
		return "24"
	}
}