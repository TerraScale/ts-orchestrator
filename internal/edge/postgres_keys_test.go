package edge

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

func TestPostgresStartupRegistersKeyBeforeForwardingFragmentedFrames(t *testing.T) {
	t.Parallel()
	key := [8]byte{0, 0, 0, 42, 0, 0, 0, 7}
	packet := binary.BigEndian.AppendUint32([]byte{'R'}, 8)
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = append(binary.BigEndian.AppendUint32(append(packet, 'K'), 12), key[:]...)
	packet = append(packet, 'Z', 0, 0, 0, 5, 'I')
	for size := 1; size <= len(packet); size++ {
		keys := new(postgresKeys)
		var release func()
		s := &postgresStartup{key: func(got [8]byte) error {
			if got != key {
				t.Fatal("backend key changed")
			}
			var err error
			release, err = keys.add(got, 54321)
			return err
		}}
		for offset := 0; offset < len(packet); offset += size {
			chunk := packet[offset:min(offset+size, len(packet))]
			if _, err := s.Write(chunk); err != nil {
				t.Fatal(err)
			}
			if offset+len(chunk) >= 22 {
				if port, ok := keys.port(key); !ok || port != 54321 {
					t.Fatal("complete key was forwarded without ownership")
				}
			}
		}
		release()
		if _, ok := keys.port(key); ok || keys.count != 0 {
			t.Fatal("disconnected key retained")
		}
	}
	for _, bad := range [][]byte{{'R', 0, 0, 0, 3}, {'K', 0, 16, 0, 1}} {
		s := &postgresStartup{key: func([8]byte) error { t.Fatal("malformed frame registered a key"); return nil }}
		if _, err := s.Write(bad); err == nil {
			t.Fatal("invalid frame accepted")
		}
	}
}

func TestPostgresKeysBoundCapacityAndRejectUnknownOrAmbiguousOwners(t *testing.T) {
	t.Parallel()
	keys := new(postgresKeys)
	var key [8]byte
	if _, ok := keys.port(key); ok {
		t.Fatal("unknown key accepted")
	}
	first, _ := keys.add(key, 1234)
	second, _ := keys.add(key, 5678)
	if _, ok := keys.port(key); ok {
		t.Fatal("ambiguous owner accepted")
	}
	first()
	first() // Teardown is idempotent and cannot remove a later owner.
	if port, ok := keys.port(key); !ok || port != 5678 {
		t.Fatal("remaining owner lost")
	}
	second()
	var releases []func()
	for i := range maxPostgresConns {
		binary.BigEndian.PutUint64(key[:], uint64(i))
		release, err := keys.add(key, 5432)
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	if _, err := keys.add([8]byte(bytes.Repeat([]byte{255}, 8)), 5432); err == nil {
		t.Fatal("unbounded key registry")
	}
	for _, release := range releases {
		release()
	}
	if keys.count != 0 || len(keys.keys) != 0 {
		t.Fatal("key reservations not reclaimed")
	}
}

func TestPostgresBackendKeyLifecycleThroughTLSListener(t *testing.T) {
	t.Parallel()
	ca, err := mesh.DeriveCA(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue("pg.edge.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	backendLn, ingress := listen(t), listen(t)
	port := backendLn.Addr().(*net.TCPAddr).Port
	e := newEdge(t.TempDir(), nil)
	e.SetRoutes(nil, map[string]int{"pg.edge.test": port})
	key := [8]byte{0, 0, 0, 42, 0, 0, 0, 7}
	packet := append(binary.BigEndian.AppendUint32([]byte{'K'}, 12), key[:]...)
	received := make(chan []byte, 1)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				var proxy [16]byte
				if _, err := io.ReadFull(conn, proxy[:]); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(proxy[14:]))); err != nil {
					return
				}
				if i == 0 {
					conn.Write(packet)
					io.Copy(io.Discard, conn)
				} else {
					body := make([]byte, 16)
					if _, err := io.ReadFull(conn, body); err == nil {
						received <- body
					}
				}
			}()
		}
	}()
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		if conn, err := ingress.Accept(); err == nil {
			e.postgresConn(conn, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{postgresALPN}})
		}
	}()
	client, err := tls.Dial("tcp", ingress.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "pg.edge.test", NextProtos: []string{postgresALPN}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(client, make([]byte, len(packet))); err != nil {
		t.Fatal(err)
	}
	request := append(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 16}, cancelRequest), key[:]...)
	e.forwardCancel(append(proxyHeader(client.LocalAddr(), client.RemoteAddr()), request...))
	select {
	case got := <-received:
		if !bytes.Equal(got, request) {
			t.Fatal("cancel did not reach the backend that emitted the key")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancel not delivered")
	}
	client.Close()
	<-ended
	if _, ok := e.pgKeys.port(key); ok {
		t.Fatal("disconnected backend key still owns cancellation")
	}
}
