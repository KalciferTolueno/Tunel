//go:build !gui

// dispatch_nogui.go is the entrypoint dispatch for the no-GUI build. When
// tunelc is compiled without the `gui` tag, --gui prints a hint and the
// default mode runs the CLI.

package main

import "errors"

// guiAvailable reports whether GUI support was compiled in. Always false in
// the no-GUI build so double-clicking the .exe without args preserves the
// old CLI behaviour (it will then complain about missing flags).
func guiAvailable() bool { return false }

func run(mode runMode, _ []string) error {
	switch mode {
	case modeGUI:
		return errors.New("la GUI no está incluida en este binario; recompila con: go build -tags gui -ldflags \"-H windowsgui\" -o tunelc.exe ./cmd/tunelc")
	default:
		return runCLI()
	}
}