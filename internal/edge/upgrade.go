package edge

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
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
	head   []byte
	opened bool
}

func (c *upgradedConn) Read(p []byte) (int, error) { return c.writer.stream.Read(p) }

func (c *upgradedConn) Write(p []byte) (int, error) {
	if c.opened {
		return c.relay(p)
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
	if _, err := c.relay(rest); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *upgradedConn) relay(p []byte) (int, error) {
	n, err := c.writer.ResponseWriter.Write(p)
	if err == nil {
		err = http.NewResponseController(c.writer.ResponseWriter).Flush()
	}
	return n, err
}

func (c *upgradedConn) Close() error                     { return c.writer.stream.Close() }
func (c *upgradedConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *upgradedConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *upgradedConn) SetDeadline(time.Time) error      { return nil }
func (c *upgradedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *upgradedConn) SetWriteDeadline(time.Time) error { return nil }
