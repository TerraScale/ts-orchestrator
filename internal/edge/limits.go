package edge

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

const maxPublicConnections = 1024
const maxSourceConnections = maxPublicConnections / 16
const bodyProgressBytes = 64 << 10
const bodyProgressWindow = 10 * time.Second

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

func edgeSource(address net.Addr) (netip.Prefix, bool) {
	var ip netip.Addr
	if tcp, ok := address.(*net.TCPAddr); ok {
		ip = tcp.AddrPort().Addr()
	} else if address != nil {
		parsed, _ := netip.ParseAddrPort(address.String())
		ip = parsed.Addr()
	}
	return addressSource(ip)
}

func addressSource(ip netip.Addr) (netip.Prefix, bool) {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return netip.Prefix{}, false
	}
	exempt := ip.IsPrivate() || ip.IsLoopback() || sharedAddressSpace.Contains(ip)
	bits := 64
	if ip.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(ip, bits).Masked(), exempt
}

type sourceSlots struct {
	mu      sync.Mutex
	sources map[netip.Prefix]int
	total   int
}

func (s *sourceSlots) take(source netip.Prefix, perSource, total int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if source.IsValid() && s.sources[source] >= perSource {
		return "source"
	}
	if s.total >= total {
		return "node"
	}
	if source.IsValid() {
		if s.sources == nil {
			s.sources = make(map[netip.Prefix]int)
		}
		s.sources[source]++
	}
	s.total++
	return ""
}

func (s *sourceSlots) release(source netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
	if source.IsValid() {
		if s.sources[source]--; s.sources[source] == 0 {
			delete(s.sources, source)
		}
	}
}

type limitedConn struct {
	net.Conn
	once   sync.Once
	slots  *sourceSlots
	source netip.Prefix
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.slots.release(c.source) })
	return err
}

type limitedListener struct {
	net.Listener
	edge     *Edge
	protocol string
	config   *tls.Config
}

func (l limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		source, exempt := edgeSource(conn.RemoteAddr())
		if exempt {
			source = netip.Prefix{}
		}
		reason := l.edge.httpConnections.take(source, maxSourceConnections, maxPublicConnections)
		if reason == "" {
			return &limitedConn{Conn: conn, slots: &l.edge.httpConnections, source: source}, nil
		}
		status := http.StatusTooManyRequests
		if reason == "node" {
			status = http.StatusServiceUnavailable
		}
		observability.RecordEdgeResponse(l.protocol, status, "connection_"+reason)
		select {
		case l.edge.refusals <- struct{}{}:
			go l.refuse(conn, status)
		default:
			conn.Close()
		}
	}
}

func (l limitedListener) refuse(conn net.Conn, status int) {
	defer func() { <-l.edge.refusals }()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if l.config != nil {
		client := tls.Server(conn, l.config)
		if err := client.Handshake(); err != nil {
			return
		}
		conn = client
		if client.ConnectionState().NegotiatedProtocol == "h2" {
			server := &http2.Server{}
			server.ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(status)
			})})
			return
		}
	}
	if _, err := http.ReadRequest(bufio.NewReader(io.LimitReader(conn, 64<<10))); err != nil {
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
}

type progressBody struct {
	io.ReadCloser
	controller http.ResponseController
	progress   int
	timedOut   atomic.Bool
	protocol   string
}

func (b *progressBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		b.timedOut.Store(true)
	}
	b.progress += n
	if err == io.EOF {
		b.controller.SetReadDeadline(time.Time{})
		if b.protocol == "http" {
			b.controller.SetWriteDeadline(time.Now().Add(bodyProgressWindow))
		}
	} else if b.progress >= bodyProgressBytes {
		b.progress %= bodyProgressBytes
		if deadlineErr := b.controller.SetReadDeadline(time.Now().Add(bodyProgressWindow)); err == nil {
			err = deadlineErr
		}
	}
	return n, err
}

func watchBody(w http.ResponseWriter, r *http.Request) error {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 || isGRPC(r) || websocketHandshake(r) || isExtendedConnect(r) {
		return nil
	}
	response := countedResponse(w)
	response.body = progressBody{ReadCloser: r.Body, controller: *http.NewResponseController(w), protocol: response.protocol}
	if response.protocol == "http" {
		if err := response.body.controller.SetWriteDeadline(time.Time{}); err != nil {
			return err
		}
	}
	if err := response.body.controller.SetReadDeadline(time.Now().Add(bodyProgressWindow)); err != nil {
		return err
	}
	r.Body = &response.body
	return nil
}

func countedResponse(w http.ResponseWriter) *responseWriter {
	for {
		if response, ok := w.(*responseWriter); ok {
			return response
		}
		w = w.(interface{ Unwrap() http.ResponseWriter }).Unwrap()
	}
}

func refuseHTTP(w http.ResponseWriter, r *http.Request, status int, reason string) {
	countedResponse(w).reason = reason
	r.Close = true
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
	w.Header().Set("Retry-After", "1")
	http.Error(w, http.StatusText(status), status)
}

type edgeRefusal struct {
	status int
	reason string
}

func (e edgeRefusal) Error() string { return e.reason }
