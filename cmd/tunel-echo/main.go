// Command tunel-echo is a tiny TCP/UDP echo server used for testing the
// reverse tunnel without depending on Python or Node.
//
// Usage:
//
//	tunel-echo -listen 127.0.0.1:3000           # TCP echo (HTTP-style)
//	tunel-echo -listen 127.0.0.1:4000 -udp       # UDP echo
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:3000", "address to listen on")
	udp := flag.Bool("udp", false, "run a UDP echo server instead of HTTP")
	flag.Parse()

	if *udp {
		runUDPEcho(*listen)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body := fmt.Sprintf(
			"Hola desde el servidor LOCAL (tunel-echo) en %s\n"+
				"Request URL: %s\n"+
				"RemoteAddr: %s\n"+
				"Time:        %s\n",
			*listen, r.URL.String(), r.RemoteAddr, time.Now().Format(time.RFC3339),
		)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprint(w, body)
	})

	srv := &http.Server{Addr: *listen, Handler: mux}
	log.Printf("tunel-echo escuchando en http://%s/", *listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("http server: %v", err)
	}
}

// runUDPEcho listens on addr and replies to every datagram with "[echo] <msg>".
func runUDPEcho(addr string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("udp listen %s: %v", addr, err)
	}
	defer pc.Close()
	log.Printf("tunel-echo escuchando en udp://%s/", addr)
	buf := make([]byte, 65535)
	for {
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := []byte(fmt.Sprintf("[echo udp %s] %s", time.Now().Format("15:04:05.000"), string(buf[:n])))
		_, _ = pc.WriteTo(resp, peer)
		log.Printf("udp echo peer=%s bytes=%d", peer, n)
	}
}