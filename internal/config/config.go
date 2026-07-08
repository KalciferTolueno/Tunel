// Package config holds shared CLI helpers for tunels and tunelc: flag parsing
// and a slog logger configured by a --log-level flag.
package config

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// LogLevel flag value, accepts: debug, info, warn, error.
type LogLevel string

// String implements flag.Value.
func (l LogLevel) String() string { return string(l) }

// Set implements flag.Value.
func (l *LogLevel) Set(s string) error {
	switch strings.ToLower(s) {
	case "debug", "info", "warn", "error":
		*l = LogLevel(strings.ToLower(s))
		return nil
	default:
		return fmt.Errorf("invalid log level %q (debug|info|warn|error)", s)
	}
}

// NewLogger returns a slog.Logger writing to w at the requested level.
// Default level is info. JSON handler is used so logs are easy to grep/parse.
func NewLogger(level LogLevel, w io.Writer) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})
	return slog.New(h)
}

// RegisterLogLevelFlag binds a --log-level flag to the given FlagSet and
// returns a pointer to the parsed value.
func RegisterLogLevelFlag(fs *flag.FlagSet, def LogLevel) *LogLevel {
	l := def
	fs.Var(&l, "log-level", "log level: debug|info|warn|error")
	return &l
}

// ParseAllowedPorts turns a comma-separated list into a set for O(1) lookup.
// Empty input returns an empty set (meaning, in the server, "any port").
func ParseAllowedPorts(s string) map[int]struct{} {
	out := map[int]struct{}{}
	if s == "" {
		return out
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil {
			continue
		}
		if n > 0 && n <= 65535 {
			out[n] = struct{}{}
		}
	}
	return out
}

// EnvOrDefault returns the env var value if set, else def.
func EnvOrDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}