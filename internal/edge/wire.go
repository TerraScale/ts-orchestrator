package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

// WirePort is the public TLS port; TerraBase listens on a distinct private port.
const WirePort = 7464

func (e *Edge) SetWireRoutes(routes map[string]int) {
	table := make(map[string]int, len(routes))
	for host, port := range routes {
		table[strings.ToLower(host)] = port
	}
	e.wire.Store(&table)
}

func (e *Edge) wireHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	_, ok := (*e.wire.Load())[strings.ToLower(host)]
	return ok
}

// runWire always retries independently of the established edge listeners.
func (e *Edge) runWire(ctx context.Context) {
	for ctx.Err() == nil {
		ln, err := e.listen("tcp", ":"+strconv.Itoa(WirePort))
		if err == nil {
			served := make(chan error, 1)
			go func() { served <- e.serveWire(ln) }()
			select {
			case <-ctx.Done():
				ln.Close()
				<-served
				return
			case err = <-served:
				ln.Close()
			}
		}
		slog.WarnContext(ctx, "edge wire listener unavailable; retrying without interrupting HTTPS", "error", err)
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (e *Edge) serveWire(ln net.Listener) error {
	config := e.certs.TLSConfig()
	config.NextProtos = nil // The wire protocol uses direct TLS without HTTP ALPN.
	getCert := config.GetCertificate
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if !e.wireHost(hello.ServerName) {
			return nil, fmt.Errorf("edge: no wire route for %q", hello.ServerName)
		}
		return getCert(hello)
	}
	slots := make(chan struct{}, maxPostgresConns)
	for {
		conn, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				e.wireConn(conn, config)
			}()
		default:
			conn.Close()
		}
	}
}

func (e *Edge) wireConn(raw net.Conn, config *tls.Config) {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(postgresHandshake))
	client := tls.Server(raw, config)
	if err := client.Handshake(); err != nil {
		return
	}
	port, ok := (*e.wire.Load())[strings.ToLower(client.ConnectionState().ServerName)]
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresHandshake)
	backend, err := dialHandoff(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	cancel()
	if err != nil {
		return
	}
	defer backend.Close()
	// Wire framing starts immediately; unlike Postgres, no PROXY header is added.
	raw.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { io.Copy(backend, client); done <- struct{}{} }()
	go func() { io.Copy(client, backend); done <- struct{}{} }()
	<-done
}
