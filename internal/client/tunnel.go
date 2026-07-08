package client

import (
	"io"
	"net"
	"sync"
)

// closeWrapper adapts a net.Conn so pipeBoth can call CloseWrite on the
// generic io.ReadWriteCloser interface. Both ends of a tunnel need CloseWrite
// so the peer's io.Copy returns promptly when the local side finishes.
type closeWrapper struct {
	net.Conn
}

var _ interface{ CloseWrite() error } = (*closeWrapper)(nil)

func (c *closeWrapper) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *closeWrapper) Close() error { return c.Conn.Close() }

var _ io.ReadWriteCloser = (*closeWrapper)(nil)

// pipeBoth copies bytes between a and b in both directions, blocking until
// either side closes or errors. Both ends are closed on return.
func pipeBoth(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if c, ok := b.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if c, ok := a.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}