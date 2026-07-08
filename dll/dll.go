// Package dll embeds the wintun.dll binary so it ships inside the tunelc.exe
// and is materialized at runtime next to the process (Windows requires the
// DLL to be loadable via LoadLibrary, which expects a real file on disk).
//
// On non-Windows targets this file produces nothing usable: callers must
// guard usage with a runtime.GOOS check.
package dll

import (
	_ "embed"
	"io"
	"os"
	"path/filepath"
)

//go:embed wintun.dll
var wintunBin []byte

// Materialize writes the embedded wintun.dll to destDir and returns the full
// path to it. If a file with the same name and length already exists, it is
// reused untouched (avoids re-writing on every run).
func Materialize(destDir string) (string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(destDir, "wintun.dll")
	if fi, err := os.Stat(path); err == nil && int(fi.Size()) == len(wintunBin) {
		return path, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, readFileFromBytes(wintunBin)); err != nil {
		return "", err
	}
	return path, nil
}

// small helper to satisfy io.Reader without bytes.NewReader import churn.
type bytesReader struct {
	b   []byte
	off int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

func readFileFromBytes(b []byte) io.Reader { return &bytesReader{b: b} }