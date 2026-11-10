package edge

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestPostgresHandshakeQuotaIsPerSource(t *testing.T) {
	t.Parallel()
	e := newEdge(t.TempDir(), nil)
	ingress := listen(t)
	served := make(chan error, 1)
	go func() { served <- e.servePostgresTLS(ingress, &tls.Config{}) }()
	t.Cleanup(func() {
		ingress.Close()
		if err := <-served; err != nil {
			t.Error(err)
		}
	})
	dial := func(ip net.IP) net.Conn {
		t.Helper()
		c, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: ip}, Timeout: 2 * time.Second}).Dial("tcp", ingress.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	for range maxPostgresHandshakes {
		dial(net.IPv4(127, 0, 0, 1))
	}
	refused := false
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		excess := dial(net.IPv4(127, 0, 0, 1))
		excess.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := excess.Read(make([]byte, 1))
		excess.Close()
		if err == nil {
			t.Fatal("idle handshake returned data")
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			continue
		}
		refused = true
		break
	}
	if !refused {
		t.Fatal("one source filled the node handshake budget instead of its own")
	}
	other := dial(net.IPv4(127, 0, 0, 2))
	if got := other.LocalAddr().(*net.TCPAddr).IP.String(); got != "127.0.0.2" {
		t.Fatalf("second source dialed as %s", got)
	}
	other.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := other.Write(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, sslRequest)); err != nil {
		t.Fatal(err)
	}
	var response [1]byte
	if _, err := io.ReadFull(other, response[:]); err != nil || response[0] != 'S' {
		t.Fatalf("second source handshake %q: %v", response, err)
	}
}
