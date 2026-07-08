//go:build vpn && windows

// tun_windows.go opens a TUN device on Windows using wintun.dll (bundled
// in dll/wintun.dll next to the .exe) via golang.zx2c4.com/wireguard/tun,
// and configures the interface with netsh (set IP / mask / gateway + bring
// interface "up").
//
// Compared to unix variants, Windows requires:
//   1. The wintun.dll file to be loadable by LoadLibrary. We materialize it
//      from the embedded byte slice in package dll next to the .exe.
//   2. The wintun adapter to be created once per name (subsequent open may
//      reuse). Adapter creation may require Administrator the first time.

package client

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/tun"

	"tunel/dll"
	"tunel/internal/protocol"
)

// wintunAdapterName is the human-readable name of the adapter. Wintun
// adapter names must be <= 128 chars; we use a short fixed value so it's
// recognisable in netsh / Control Panel.
const wintunAdapterName = "TunelVPN"

// wgTUN wraps tun.Device to satisfy our minimal TUNDevice interface.
type wgTUN struct {
	d tun.Device
}

func (w *wgTUN) Name() (string, error) {
	name, err := w.d.Name()
	return name, err
}

func (w *wgTUN) Read(buf []byte, off int) (int, error) {
	// wireguard/tun on Windows uses vectored IO: we batch a single buffer.
	bufs := [][]byte{buf[off:]}
	sizes := make([]int, 1)
	_, err := w.d.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	return sizes[0], nil
}

func (w *wgTUN) Write(buf []byte, off int) (int, error) {
	bufs := [][]byte{buf[off:]}
	return w.d.Write(bufs, 0)
}

func (w *wgTUN) Close() error { return w.d.Close() }

// Events returns a channel of tun up/down events converted to our TunEvent.
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

// openTUN materializes the embedded wintun.dll next to the .exe (so the
// wireguard/tun package's LoadLibrary call can find it) and opens a new TUN
// adapter named wintunAdapterName. The MTU is set to 1400 (matches the
// yamux+TLS path overhead). Windows requires Administrator privileges the
// first time the adapter is installed.
func openTUN(ok protocol.AuthOK) (TUNDevice, error) {
	dir := exeDir()
	dllPath, err := dll.Materialize(dir)
	if err != nil {
		return nil, fmt.Errorf("materialize wintun.dll: %w", err)
	}
	_ = filepath.Dir(dllPath) // keep imported symbol used for clarity
	// Ensure the process CWD is the .exe folder so LoadLibrary's default
	// search (which looks in the application directory first) finds the DLL.
	_ = os.Chdir(dir)

	dev, err := tun.CreateTUN(wintunAdapterName, 1400)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w (require admin? wintun.dll at %s)", err, dllPath)
	}
	return &wgTUN{d: dev}, nil
}

// configureTUN assigns the VPN IP and mask to the adapter, sets MTU, and adds
// a route to the VPN subnet. Windows uses "netsh interface ip".
func configureTUN(dev TUNDevice, ok protocol.AuthOK) error {
	name, err := dev.Name()
	if err != nil {
		return fmt.Errorf("get tun name: %w", err)
	}
	cmds := []string{
		"netsh interface ip set address name=" + doubleQuote(name) + " static " + ok.VPNIP + " " + ok.VPNMask + " " + ok.VPNGateway,
		"netsh interface ip set subinterface " + doubleQuote(name) + " mtu=1400",
		"route add " + ok.VPNSubnet + " mask " + ok.VPNMask + " " + ok.VPNGateway + " metric 1",
	}
	for _, c := range cmds {
		out, err := exec.Command("cmd", "/c", c).CombinedOutput()
		if err != nil {
			return fmt.Errorf("config cmd %q: %w: %s", c, err, out)
		}
	}
	return nil
}

// doubleQuote wraps a name in double quotes for netsh.
func doubleQuote(s string) string {
	if strings.HasPrefix(s, "\"") {
		return s
	}
	return "\"" + s + "\""
}

// keep the errors package referenced so unused linters don't complain; we'll
// expand usage with better error wrapping shortly.
var _ = errors.New