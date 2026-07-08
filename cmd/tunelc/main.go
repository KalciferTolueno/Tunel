// Command tunelc is the client side of the reverse tunnel. Run it on the
// machine where your local service lives (the one you want to expose).
//
// tunelc runs in two modes:
//
//   - CLI mode (default): pass --server, --token, --remote, --local, --cacert.
//     Behaviour is identical to the original tunelc.
//   - GUI mode: pass --gui (or simply double-click the exe). Opens a Fyne
//     window where you can fill the same fields visually and click Connect.
//     The GUI build is only available when the binary is compiled with the
//     `gui` build tag; otherwise --gui prints a hint and exits.
//
// Build:
//
//	go build                       -o tunelc.exe ./cmd/tunelc   # CLI only, no CGO
//	go build -tags gui -ldflags "-H windowsgui" -o tunelc.exe ./cmd/tunelc   # CLI+GUI
package main

import (
	"fmt"
	"os"
	"strings"
)

// runMode tells main which entrypoint to dispatch to. Implementations live in
// dispatch_nogui.go (build tag !gui) and gui.go (build tag gui).
type runMode int

const (
	modeCLI runMode = iota
	modeGUI
)

// hasGuiArg reports whether --gui (or -gui) appears anywhere in os.Args. We
// cannot use the flag package directly here because the CLI defines its own
// FlagSet inside runCLI; pre-parsing would reject unknown flags.
func hasGuiArg() bool {
	for _, a := range os.Args[1:] {
		if a == "--gui" || a == "-gui" || strings.HasPrefix(a, "--gui=") {
			return true
		}
	}
	return false
}

// noArgs reports whether the user provided any arguments at all. When no
// args are given and the binary was built with GUI support, we launch the
// GUI so double-clicking the .exe does something useful.
func noArgs() bool { return len(os.Args) <= 1 }

func main() {
	mode := modeCLI
	if hasGuiArg() || (noArgs() && guiAvailable()) {
		mode = modeGUI
	}
	if err := run(mode, nil); err != nil {
		fmt.Fprintf(os.Stderr, "tunelc: %v\n", err)
		os.Exit(1)
	}
}