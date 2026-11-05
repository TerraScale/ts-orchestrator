package edge

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

func TestPostgresSeparateCapacityAdmitsCancellationAtFullSessions(t *testing.T) {
	t.Parallel()
	regions := startRegions(t, terraBase, "ams")
	e := regions["fra"].edge
	backend, ingress := listen(t), listen(t)
	port := backend.Addr().(*net.TCPAddr).Port
	e.SetRoutes(nil, map[string]int{"pg.edge.test": port})
	ca, err := mesh.DeriveCA(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue("pg.edge.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	server := &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{postgresALPN}}
	served := make(chan error, 1)
	go func() { served <- e.servePostgresTLS(ingress, server) }()
	t.Cleanup(func() {
		ingress.Close()
		if err := <-served; err != nil {
			t.Error(err)
		}
	})
	startup := []byte{0, 0, 0, 9, 0, 3, 0, 0, 0}
	ready := []byte{'Z', 0, 0, 0, 5, 'I'}
	var sequence atomic.Uint64
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var header [16]byte
				if _, err := io.ReadFull(c, header[:]); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(header[14:]))); err != nil {
					return
				}
				body := make([]byte, len(startup))
				if _, err := io.ReadFull(c, body); err != nil || !bytes.Equal(body, startup) {
					return
				}
				key := binary.BigEndian.AppendUint64(nil, sequence.Add(1))
				reply := append(binary.BigEndian.AppendUint32([]byte{'K'}, 12), key...)
				if _, err := c.Write(append(reply, ready...)); err != nil {
					return
				}
				c.SetDeadline(time.Time{})
				io.Copy(io.Discard, c)
			}()
		}
	}()
	dial := func() net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", ingress.Addr().String(), 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(10 * time.Second))
		return c
	}
	connect := func(mode string) net.Conn {
		t.Helper()
		c := dial()
		if mode == "raw" {
			return c
		}
		config := &tls.Config{RootCAs: roots, ServerName: "pg.edge.test"}
		if mode == "sslrequest" {
			if _, err := c.Write(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, sslRequest)); err != nil {
				t.Fatal(err)
			}
			var response [1]byte
			if _, err := io.ReadFull(c, response[:]); err != nil || response[0] != 'S' {
				t.Fatalf("SSLRequest reply %q: %v", response, err)
			}
		} else {
			config.NextProtos = []string{postgresALPN}
		}
		client := tls.Client(c, config)
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		return client
	}
	normal := func() net.Conn {
		t.Helper()
		c := connect("direct")
		if _, err := c.Write(startup); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 13+len(ready))
		if _, err := io.ReadFull(c, got); err != nil || got[0] != 'K' || !bytes.Equal(got[13:], ready) {
			t.Fatalf("normal session did not receive backend ready: %x, %v", got, err)
		}
		c.SetDeadline(time.Time{})
		return c
	}
	t.Cleanup(func() {
		postgresCapacityQuiescent(t, e.pgSessions)
		postgresCapacityQuiescent(t, e.pgHandshakes)
	})
	var clients []net.Conn
	for range maxPostgresConns {
		clients = append(clients, normal())
	}
	if len(e.pgSessions) != maxPostgresConns || len(e.pgHandshakes) != 0 {
		t.Fatal("established sessions retained handshake capacity or exceeded session bound")
	}
	e.pgKeys.mu.Lock()
	keyCount := e.pgKeys.count
	e.pgKeys.mu.Unlock()
	if keyCount != maxPostgresConns {
		t.Fatal("full normal population and backend-key registry capacity disagree")
	}
	// Start negotiations together; each S proves the real accept loop admitted it.
	var pending []net.Conn
	responses := make(chan bool, maxPostgresHandshakes)
	for range maxPostgresHandshakes {
		c := dial()
		pending = append(pending, c)
		go func() {
			_, err := c.Write(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, sslRequest))
			var response [1]byte
			if err == nil {
				_, err = io.ReadFull(c, response[:])
			}
			responses <- err == nil && response[0] == 'S'
		}()
	}
	for range maxPostgresHandshakes {
		if !<-responses {
			t.Fatal("pending handshake not admitted")
		}
	}
	for range 8 {
		excess := dial()
		if _, err := excess.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection beyond handshake budget stayed open")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("excess accept waited instead of closing immediately")
		}
		excess.Close()
	}
	for _, c := range pending {
		c.Close()
	}
	postgresCapacityQuiescent(t, e.pgHandshakes)
	for _, complete := range []bool{true, false} {
		refused := connect("direct").(*tls.Conn)
		if _, err := refused.Write(startup[:8]); err != nil {
			t.Fatal(err)
		}
		failure, err := io.ReadAll(refused) // Go also accepts bare transport EOF at a TLS record boundary.
		if err != nil || !bytes.Contains(failure, []byte("C53300\x00")) {
			t.Fatalf("full normal population did not return 53300 and EOF: %q, %v", failure, err)
		}
		if complete {
			if _, err := refused.Write(startup[8:]); err != nil { // A separate TLS record.
				t.Fatal(err)
			}
			if err := refused.CloseWrite(); err != nil {
				t.Fatal(err)
			}
		}
		// The incomplete peer stays open: only the server deadline can free its permit.
		postgresCapacityQuiescent(t, e.pgHandshakes)
		refused.Close()
	}
	// Seed ownership in the fourth region; delivery must be observed there.
	cancelPort, delivered, headers := echoBackend(t)
	key := [8]byte{0, 0, 0, 42, 0, 0, 0, 7}
	release, err := regions["ams"].edge.pgKeys.add(key, cancelPort)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	request := append(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 16}, cancelRequest), key[:]...)
	for _, mode := range []string{"raw", "direct", "sslrequest"} {
		c := connect(mode)
		wantHeader := proxyHeader(c.LocalAddr(), c.RemoteAddr())
		if _, err := c.Write(request); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("cancellation unexpectedly returned data")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("cancellation connection did not close")
		}
		c.Close()
		select {
		case got := <-delivered:
			if !bytes.Equal(got, request) || !bytes.Equal(<-headers, wantHeader) {
				t.Fatalf("%s cancellation reached wrong target or lost client address", mode)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s cancellation did not reach unique remote owner at full capacity", mode)
		}
	}
	if len(e.pgSessions) != maxPostgresConns {
		t.Fatal("refusal or cancellation consumed/released a normal session")
	}
	clients[0].Close()
	// A channel reservation synchronizes with teardown without polling or sleeps.
	select {
	case e.pgSessions <- struct{}{}:
		<-e.pgSessions
	case <-time.After(10 * time.Second):
		t.Fatal("disconnected normal session did not release capacity")
	}
	clients[0] = normal()
	if len(e.pgSessions) != maxPostgresConns {
		t.Fatal("normal capacity did not recover")
	}
}

// Reserve every slot to wait for real handlers to release their reservations,
// then restore the empty pool. This is only a deterministic teardown barrier.
func postgresCapacityQuiescent(t *testing.T, slots chan struct{}) {
	t.Helper()
	timer := time.NewTimer(2 * postgresHandshake)
	defer timer.Stop()
	for range cap(slots) {
		select {
		case slots <- struct{}{}:
		case <-timer.C:
			t.Fatal("postgres capacity was not released")
		}
	}
	for range cap(slots) {
		<-slots
	}
}
