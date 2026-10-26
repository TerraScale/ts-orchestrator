package edge

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// loopbackFixture serves the TerraBase loopback relay to a backend address
// that refuses until the test binds it, as during a stop-first handoff.
func loopbackFixture(t *testing.T, wait time.Duration) (loopback, backend string) {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend = probe.Addr().String()
	probe.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveTerraBase(ln, func() (string, error) { return backend, nil }, wait)
	return ln.Addr().String(), backend
}

func TestTerraBaseLoopbackWaitsOutStopFirstHandoff(t *testing.T) {
	loopback, backend := loopbackFixture(t, 5*time.Second)
	started := time.Now()
	go func() {
		time.Sleep(300 * time.Millisecond) // the new task binds its internal listener
		ln, err := net.Listen("tcp", backend)
		if err != nil {
			return
		}
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	client, err := net.Dial("tcp", loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte("GET /readyz")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("GET /readyz"))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("relay during handoff: %v", err)
	}
	if string(got) != "GET /readyz" {
		t.Fatalf("relayed %q", got)
	}
	if time.Since(started) < 300*time.Millisecond {
		t.Fatal("relay answered before the new task bound its listener")
	}
}

func TestTerraBaseLoopbackFailsClosedPastBound(t *testing.T) {
	loopback, _ := loopbackFixture(t, 300*time.Millisecond)
	client, err := net.Dial("tcp", loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = client.Write([]byte("GET /readyz"))
	n, err := client.Read(make([]byte, 1))
	if n != 0 || err == nil {
		t.Fatalf("read %d bytes, err %v; want the connection closed", n, err)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("relay kept the connection past its bound")
	}
}

func TestTerraBaseBindErrorNamesHostShortcut(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	_, err = net.Listen("tcp", held.Addr().String())
	if err == nil {
		t.Fatal("second bind succeeded")
	}
	if msg := terrabaseBindError(err).Error(); !strings.Contains(msg, "systemctl disable --now fr1-terrabase-loopback.socket") {
		t.Fatalf("bind error %q does not name the host shortcut", msg)
	}
}
