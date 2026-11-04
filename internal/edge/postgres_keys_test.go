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
			e.postgresConn(conn, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{postgresALPN}}, func() {})
		}
	}()
	client, err := tls.Dial("tcp", ingress.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "pg.edge.test", NextProtos: []string{postgresALPN}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := client.Write([]byte{0, 0, 0, 8, 0, 3, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, make([]byte, len(packet))); err != nil {
		t.Fatal(err)
	}
	request := append(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 16}, cancelRequest), key[:]...)
	go func() {
		if conn, err := ingress.Accept(); err == nil {
			e.postgresConn(conn, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{postgresALPN}}, func() {})
		}
	}()
	cancel, err := tls.Dial("tcp", ingress.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "pg.edge.test", NextProtos: []string{postgresALPN}})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel.Close()
	cancel.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := cancel.Write(request); err != nil {
		t.Fatal(err)
	}
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
