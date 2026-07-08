package server

import (
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"runtime"
	"time"
)

// DashboardConfig holds the admin web UI bind address.
type DashboardConfig struct {
	Bind string // e.g. ":9001" or "127.0.0.1:9001"
}

var startTime = time.Now()

// RunDashboard starts an HTTP server that renders live peer stats.
func RunDashboard(cfg DashboardConfig, srv *Server) error {
	if cfg.Bind == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		renderPage(w, srv)
	})
	mux.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
		renderJSON(w, srv)
	})
	mux.HandleFunc("/api/rooms", func(w http.ResponseWriter, r *http.Request) {
		renderRoomsJSON(w, srv)
	})
	server := &http.Server{Addr: cfg.Bind, Handler: mux}
	srv.logger.Info("dashboard listening", "bind", cfg.Bind)
	return server.ListenAndServe()
}

// pageData is the template model.
type pageData struct {
	Uptime    string
	Peers     int
	Goroutines int
	MemMB     uint64
	Rows      []peerRow
}

type peerRow struct {
	IP       string
	Pubkey   string
	Endpoint string
	TX       int64
	RX       int64
}

const tplHTML = `<!DOCTYPE html>
<html><head><meta charset=utf-8><title>Tunel VPN Dashboard</title>
<meta http-equiv=refresh content=5>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:2em auto;background:#0d1117;color:#c9d1d9}
h1{color:#58a6ff}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #30363d;padding:6px 10px;text-align:left}
th{background:#161b22}
.mono{font-family:monospace}
.gray{color:#8b949e}
</style></head><body>
<h1>Tunel VPN Dashboard</h1>
<p class=gray>uptime {{.Uptime}} · {{.Peers}} peers · {{.Goroutines}} goroutines · {{.MemMB}} MB</p>
<table>
<tr><th>IP</th><th>Pubkey</th><th>STUN</th><th>TX</th><th>RX</th></tr>
{{range .Rows}}<tr>
<td class=mono>{{.IP}}</td>
<td class=mono title="{{.Pubkey}}">{{trunc .Pubkey}}</td>
<td>{{.Endpoint}}</td>
<td>{{.TX}}</td>
<td>{{.RX}}</td>
</tr>{{end}}</table>
<p class=gray>auto-refresh 5s</p>
</body></html>`

var tpl = template.Must(template.New("dash").Funcs(template.FuncMap{
	"trunc": func(s string) string {
		if len(s) > 12 {
			return s[:12] + "..."
		}
		return s
	},
}).Parse(tplHTML))

func renderPage(w http.ResponseWriter, srv *Server) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	rows := collectRows(srv)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, pageData{
		Uptime:     time.Since(startTime).Round(time.Second).String(),
		Peers:      len(rows),
		Goroutines: runtime.NumGoroutine(),
		MemMB:      m.Alloc / 1024 / 1024,
		Rows:       rows,
	})
}

func renderJSON(w http.ResponseWriter, srv *Server) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(collectRows(srv))
}

func collectRows(srv *Server) []peerRow {
	if srv.vpn() == nil {
		return nil
	}
	all := srv.vpn().allPeers()
	out := make([]peerRow, 0, len(all))
	for _, p := range all {
		out = append(out, peerRow{
			IP:       net.IP(p.ip[:]).String(),
			Pubkey:   p.pubkey,
			Endpoint: p.stunEndpoint,
			TX:       p.txPackets.Load(),
			RX:       p.rxPackets.Load(),
		})
	}
	return out
}

// --- room-aware API ---

type roomData struct {
	Name   string
	Subnet string
	Size   int
	Rows   []peerRow
}

func renderRoomsJSON(w http.ResponseWriter, srv *Server) {
	if srv.vpn() == nil {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("[]"))
		return
	}
	rooms := srv.vpn().roomsList()
	items := make([]roomData, 0, len(rooms))
	for _, r := range rooms {
		rows := collectRoomRows(r)
		items = append(items, roomData{
			Name:   r.Name,
			Subnet: r.cidr(),
			Size:   len(rows),
			Rows:   rows,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(items)
}

func collectRoomRows(r *Room) []peerRow {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]peerRow, 0, len(r.peers))
	for ip, p := range r.peers {
		out = append(out, peerRow{
			IP:       net.IP(ip[:]).String(),
			Pubkey:   p.pubkey,
			Endpoint: p.stunEndpoint,
			TX:       p.txPackets.Load(),
			RX:       p.rxPackets.Load(),
		})
	}
	return out
}