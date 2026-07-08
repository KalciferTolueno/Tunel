package client

import "time"

// State represents the high-level lifecycle state of a tunelc client. It is
// surfaced to observers (the GUI) via the OnEvent callback in Config, so the
// UI can react to transitions without scraping log lines.
type State int

const (
	// StateIdle is the initial pre-Run state.
	StateIdle State = iota
	// StateConnecting means a dial + auth handshake is in progress.
	StateConnecting
	// StateConnected means the tunnel is fully established and serving streams.
	StateConnected
	// StateReconnecting means the previous session died and we are waiting
	// (backoff) before the next dial attempt.
	StateReconnecting
	// StateError is a terminal-ish state: all attempts exhausted in finite
	// mode, or a fatal config error.
	StateError
	// StateStopped is the clean shutdown state after ctx cancellation.
	StateStopped
)

// String returns a short human readable label for the state.
func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	case StateError:
		return "error"
	case StateStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// Event is a single state transition delivered to the OnEvent observer. The
// GUI uses Msg for the live log panel and State for the status indicator.
type Event struct {
	State State
	Msg   string
	Time  time.Time
}

// emit delivers an event to the configured observer (if any). Safe to call
// with a nil observer; it is a no-op.
func (c *Client) emit(s State, msg string) {
	if c.cfg.OnEvent == nil {
		return
	}
	e := Event{State: s, Msg: msg, Time: time.Now()}
	c.cfg.OnEvent(e)
}