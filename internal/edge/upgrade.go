package edge

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"
)

func upgradeExtendedConnect(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, *http.Request) {
	protocol := r.Header.Get(":protocol")
	upgraded := r.Clone(r.Context())
	upgraded.Method = http.MethodGet
	upgraded.Header.Del(":protocol")
	upgraded.Header.Set("Connection", "Upgrade")
	upgraded.Header.Set("Upgrade", protocol)
	if strings.EqualFold(protocol, "websocket") {
		key := make([]byte, 16)
		_, _ = rand.Read(key)
		upgraded.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(key))
	}
	upgraded.Body = http.NoBody
	upgraded.ContentLength = 0
	return &upgradedWriter{ResponseWriter: w, stream: r.Body}, upgraded
}

type upgradedWriter struct {
	http.ResponseWriter
	stream  io.ReadCloser
	started bool
}

func (u *upgradedWriter) Unwrap() http.ResponseWriter { return u.ResponseWriter }

func (u *upgradedWriter) WriteHeader(code int) {
	if code >= http.StatusOK {
		u.started = true
	}
	if code/100 == 2 {
		code = http.StatusBadGateway
	}
	u.ResponseWriter.WriteHeader(code)
}

func (u *upgradedWriter) Write(p []byte) (int, error) {
	if !u.started {
		u.WriteHeader(http.StatusOK)
	}
	return u.ResponseWriter.Write(p)
}

func (u *upgradedWriter) FlushError() error {
	if !u.started {
		u.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(u.ResponseWriter).Flush()
}

func (u *upgradedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn := &upgradedConn{writer: u}
	return conn, bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)), nil
}

type upgradedConn struct {
	writer *upgradedWriter
	mu     sync.Mutex
	head   []byte
	opened bool
	closed bool
}

func (c *upgradedConn) Read(p []byte) (int, error) { return c.writer.stream.Read(p) }

func (c *upgradedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.opened {
		return flushWithin(c.writer.ResponseWriter, p)
	}
	c.head = append(c.head, p...)
	end := bytes.Index(c.head, []byte("\r\n\r\n"))
	if end < 0 {
		return len(p), nil
	}
	rest := c.head[end+4:]
	c.head = nil
	c.opened = true
	header := c.writer.Header()
	for _, name := range []string{"Connection", "Upgrade", "Sec-WebSocket-Accept"} {
		header.Del(name)
	}
	c.writer.ResponseWriter.WriteHeader(http.StatusOK)
	if _, err := flushWithin(c.writer.ResponseWriter, rest); err != nil {
		return 0, err
	}
	return len(p), nil
}

func flushWithin(w http.ResponseWriter, p []byte) (int, error) {
	controller := http.NewResponseController(w)
	return writeWithin(controller, func() (int, error) {
		n, err := w.Write(p)
		if err == nil {
			err = controller.Flush()
		}
		return n, err
	})
}

func writeWithin(client interface{ SetWriteDeadline(time.Time) error }, write func() (int, error)) (int, error) {
	if err := client.SetWriteDeadline(time.Now().Add(clientIdleTimeout)); err != nil {
		return 0, err
	}
	n, err := write()
	if err == nil {
		err = client.SetWriteDeadline(time.Time{})
	}
	return n, err
}

func (c *upgradedConn) Close() error {
	if !c.mu.TryLock() {
		_ = http.NewResponseController(c.writer.ResponseWriter).SetWriteDeadline(time.Now())
		c.mu.Lock()
	}
	c.closed = true
	c.mu.Unlock()
	return c.writer.stream.Close()
}

func (c *upgradedConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *upgradedConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *upgradedConn) SetDeadline(time.Time) error      { return nil }
func (c *upgradedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *upgradedConn) SetWriteDeadline(time.Time) error { return nil }

const websocketAcceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type hijackWriter struct{ http.ResponseWriter }

func (w hijackWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffered, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return hijackedConn{conn}, buffered, nil
}

type hijackedConn struct{ net.Conn }

func (c hijackedConn) Write(p []byte) (int, error) {
	return writeWithin(c.Conn, func() (int, error) { return c.Conn.Write(p) })
}

func websocketHandshake(r *http.Request) bool {
	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	return r.Method == http.MethodGet && httpguts.HeaderValuesContainsToken(r.Header["Upgrade"], "websocket") &&
		httpguts.HeaderValuesContainsToken(r.Header["Connection"], "Upgrade") && r.Header.Get("Sec-WebSocket-Version") == "13" && err == nil && len(key) == 16
}

type upgradeTunnel struct{ http.RoundTripper }

func (t upgradeTunnel) RoundTrip(req *http.Request) (*http.Response, error) {
	connect := req.Clone(req.Context())
	connect.Method = http.MethodConnect
	connect.Header.Set(":protocol", "websocket")
	connect.Header.Del("Sec-WebSocket-Key")
	stream, client := io.Pipe()
	connect.Body = stream
	response, err := t.RoundTripper.RoundTrip(connect)
	if err != nil || response.StatusCode/100 != 2 {
		return response, err
	}
	accept := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + websocketAcceptGUID))
	response.Header.Set("Connection", "Upgrade")
	response.Header.Set("Upgrade", "websocket")
	response.Header.Set("Sec-WebSocket-Accept", base64.StdEncoding.EncodeToString(accept[:]))
	return &http.Response{
		Status: "101 Switching Protocols", StatusCode: http.StatusSwitchingProtocols, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: response.Header, Body: tunnelConn{response.Body, client}, Request: req,
	}, nil
}

type tunnelConn struct {
	io.ReadCloser
	*io.PipeWriter
}

func (c tunnelConn) CloseWrite() error { return c.PipeWriter.Close() }

func (c tunnelConn) Close() error {
	_ = c.PipeWriter.Close()
	return c.ReadCloser.Close()
}
