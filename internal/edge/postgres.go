package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

// PostgresPort is the public Postgres port. Clients must use TLS (sslmode=require
// or PG17 sslnegotiation=direct with ALPN "postgresql"); the decrypted stream
// goes to the loopback Postgres port of the service owning the SNI hostname.
// Plaintext never reaches a backend.
const PostgresPort = 5432

const (
	postgresHandshake = 10 * time.Second
	// maxPostgresConns protects the host; sessions are long-lived.
	maxPostgresConns = 1024
	postgresALPN     = "postgresql"
	// Startup-family request codes (Postgres protocol, "Message Formats").
	cancelRequest = 80877102
	sslRequest    = 80877103
	gssencRequest = 80877104
)

func (e *Edge) servePostgres(ln net.Listener) error {
	config := e.certs.TLSConfig()
	config.NextProtos = []string{postgresALPN}
	getCert := config.GetCertificate
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if !e.postgresHost(hello.ServerName) {
			return nil, fmt.Errorf("edge: no postgres route for %q", hello.ServerName)
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
			// Accept errors (EMFILE, ECONNABORTED) are transient; :443 retries them too.
			slog.Warn("edge postgres accept", "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				e.postgresConn(conn, config)
			}()
		default:
			conn.Close()
		}
	}
}

// bufConn reads through r so bytes peeked before the TLS handshake are not lost.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// postgresConn negotiates TLS (accepted TCP connections already use keepalive)
// and proxies the session; it closes the connection when either side ends.
func (e *Edge) postgresConn(raw net.Conn, config *tls.Config) {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(postgresHandshake))
	conn := bufConn{raw, bufio.NewReader(raw)}
	if first, err := conn.r.Peek(1); err != nil {
		return
	} else if first[0] == 0x16 { // a TLS record: PG17 sslnegotiation=direct
		e.proxyPostgres(conn, config, true)
		return
	}
	for gssDeclined := false; ; gssDeclined = true {
		var head [8]byte
		if _, err := io.ReadFull(conn, head[:]); err != nil {
			return
		}
		length, code := binary.BigEndian.Uint32(head[:4]), binary.BigEndian.Uint32(head[4:])
		switch {
		case length == 8 && code == sslRequest:
			if _, err := conn.Write([]byte{'S'}); err == nil {
				e.proxyPostgres(conn, config, false)
			}
			return
		case length == 8 && code == gssencRequest && !gssDeclined:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
		case length == 16 && code == cancelRequest:
			// The process ID and cancellation secret identify one live backend.
			body := make([]byte, 16)
			copy(body, head[:])
			if _, err := io.ReadFull(conn, body[8:]); err == nil {
				e.forwardCancel(append(proxyHeader(raw.RemoteAddr(), raw.LocalAddr()), body...))
			}
			return
		default:
			conn.Write(postgresError("28000", "TLS is required: use sslmode=require"))
			// Let the client read the error before close; unread input would reset it.
			if tcp, ok := raw.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}
			io.Copy(io.Discard, io.LimitReader(conn, 64<<10))
			return
		}
	}
}

func (e *Edge) proxyPostgres(conn net.Conn, config *tls.Config, direct bool) {
	client := tls.Server(conn, config)
	if err := client.Handshake(); err != nil {
		return
	}
	state := client.ConnectionState()
	// Direct TLS must say it speaks Postgres; after SSLRequest, ALPN is optional.
	if p := state.NegotiatedProtocol; p != postgresALPN && (direct || p != "") {
		return
	}
	port, ok := e.postgresPort(state.ServerName)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresHandshake)
	backend, err := dialHandoff(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	cancel()
	if err != nil {
		slog.Warn("edge postgres backend", "host", state.ServerName, "error", err)
		client.Write(postgresError("57P03", "the database is not accepting connections; retry shortly"))
		return
	}
	defer backend.Close()
	// The backend sees only loopback; the header names the client first.
	if _, err := backend.Write(proxyHeader(conn.RemoteAddr(), conn.LocalAddr())); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	var release func()
	defer func() {
		if release != nil {
			release()
		}
	}()
	observer := &postgresStartup{key: func(key [8]byte) error {
		var err error
		release, err = e.pgKeys.add(key, port)
		return err
	}}
	go func() { io.Copy(backend, client); done <- struct{}{} }()
	go func() { io.Copy(client, io.TeeReader(backend, observer)); done <- struct{}{} }()
	<-done
	backend.Close()
	client.Close()
	<-done // Both copies finish before removing their backend key.
}

// proxyHeader is a PROXY protocol v2 header (HAProxy spec, section 2.2) for a
// TCP connection from src to dst, without TLVs: the signature, 0x21 (version 2,
// PROXY), the family (0x11 TCP4 or 0x21 TCP6), the address block length and the
// source address, destination address, source port and destination port.
// IPv4-mapped IPv6 addresses travel as TCP4. A non-TCP pair gets a LOCAL header.
func proxyHeader(src, dst net.Addr) []byte {
	header := []byte("\r\n\r\n\x00\r\nQUIT\n")
	s, sok := src.(*net.TCPAddr)
	d, dok := dst.(*net.TCPAddr)
	if !sok || !dok {
		return append(header, 0x20, 0x00, 0, 0)
	}
	header = append(header, 0x21)
	sIP, dIP := s.IP.To4(), d.IP.To4()
	family := byte(0x11)
	if sIP == nil || dIP == nil {
		sIP, dIP, family = s.IP.To16(), d.IP.To16(), 0x21
	}
	header = append(header, family)
	header = binary.BigEndian.AppendUint16(header, uint16(2*len(sIP)+4))
	header = append(append(header, sIP...), dIP...)
	header = binary.BigEndian.AppendUint16(header, uint16(s.Port))
	return binary.BigEndian.AppendUint16(header, uint16(d.Port))
}

// forwardCancel sends a CancelRequest only to the live owner of the complete
// backend key. The request starts with the client's PROXY header.
func (e *Edge) forwardCancel(request []byte) {
	if len(request) < 16 {
		return
	}
	key := [8]byte(request[len(request)-8:])
	port, ok := e.pgKeys.port(key)
	if !ok {
		return
	}
	backend, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return
	}
	defer backend.Close()
	backend.SetDeadline(time.Now().Add(2 * time.Second))
	backend.Write(request)
}

// postgresError is a FATAL ErrorResponse with an SQLSTATE code.
func postgresError(code, message string) []byte {
	body := []byte{}
	for _, field := range []string{"SFATAL", "VFATAL", "C" + code, "M" + message} {
		body = append(append(body, field...), 0)
	}
	body = append(body, 0)
	return append(binary.BigEndian.AppendUint32([]byte{'E'}, uint32(4+len(body))), body...)
}

func (e *Edge) postgresHost(host string) bool {
	_, ok := e.postgresPort(host)
	return ok
}

func (e *Edge) postgresPort(host string) (int, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	port, ok := (*e.postgres.Load())[strings.ToLower(host)]
	return port, ok
}
