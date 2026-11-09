package edge

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/edge/extendedconnect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func init() { extendedconnect.Restore() }

const (
	tunnelWindow    = 1 << 18
	tunnelHandshake = 60 * time.Second
	tunnelStreamID  = 1
)

var errTunnelClosed = errors.New("extended CONNECT tunnel closed")

var tunnelSkippedHeaders = map[string]bool{
	":protocol": true, "host": true, "connection": true, "keep-alive": true, "proxy-connection": true,
	"transfer-encoding": true, "upgrade": true, "te": true,
}

func isExtendedConnect(r *http.Request) bool {
	return r.Method == http.MethodConnect && r.Header.Get(":protocol") != ""
}

func relayTunnel(w http.ResponseWriter, r *http.Request, transport http.RoundTripper) {
	out := r.Clone(r.Context())
	out.URL = &url.URL{Scheme: "http", Host: terrabaseLoopback, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	out.Host = r.Host
	out.RequestURI = ""
	response, err := transport.RoundTrip(out)
	if err != nil {
		slog.WarnContext(r.Context(), "extended CONNECT tunnel failed", "path", r.URL.Path, "protocol", r.Header.Get(":protocol"), "error", err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	maps.Copy(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	flusher := http.NewResponseController(w)
	if flusher.Flush() != nil {
		return
	}
	buffer := make([]byte, 32<<10)
	for {
		n, err := response.Body.Read(buffer)
		if n > 0 {
			if _, werr := w.Write(buffer[:n]); werr != nil || flusher.Flush() != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

type tunnelTransport struct {
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

func (t tunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	conn, err := t.dial(ctx, "tcp", req.URL.Host)
	if err != nil {
		closeBody(req)
		return nil, err
	}
	s := &tunnelStream{
		conn: conn, framer: http2.NewFramer(conn, bufio.NewReader(conn)),
		sendConn: 65535, sendStream: 65535, maxFrame: 16384,
		answer: make(chan *http.Response, 1), failed: make(chan struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	s.framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	s.framer.MaxHeaderListSize = 64 << 10
	s.stop = context.AfterFunc(ctx, func() { s.fail(ctx.Err()) })
	_ = conn.SetDeadline(time.Now().Add(tunnelHandshake))
	if err := s.open(req); err != nil {
		s.Close()
		closeBody(req)
		return nil, err
	}
	go s.read()
	select {
	case response := <-s.answer:
		_ = conn.SetDeadline(time.Time{})
		response.Request = req
		if response.StatusCode/100 == 2 {
			go s.send(req.Body)
		} else {
			closeBody(req)
		}
		return response, nil
	case <-s.failed:
		s.Close()
		closeBody(req)
		return nil, s.failure()
	}
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

type tunnelStream struct {
	conn   net.Conn
	framer *http2.Framer
	stop   func() bool
	answer chan *http.Response
	failed chan struct{}
	wmu    sync.Mutex

	mu         sync.Mutex
	cond       *sync.Cond
	sendConn   int64
	sendStream int64
	maxFrame   uint32
	recv       []byte
	recvEnd    bool
	answered   bool
	err        error
}

func (s *tunnelStream) open(req *http.Request) error {
	if _, err := io.WriteString(s.conn, http2.ClientPreface); err != nil {
		return err
	}
	err := s.framer.WriteSettings(http2.Setting{ID: http2.SettingEnablePush}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: tunnelWindow})
	if err == nil {
		err = s.framer.WriteWindowUpdate(0, tunnelWindow-65535)
	}
	if err != nil {
		return err
	}
	frame, err := s.framer.ReadFrame()
	if err != nil {
		return err
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok || settings.IsAck() {
		return fmt.Errorf("upstream opened HTTP/2 with %v instead of SETTINGS", frame.Header().Type)
	}
	if enabled, _ := settings.Value(http2.SettingEnableConnectProtocol); enabled != 1 {
		return errors.New("upstream does not support extended CONNECT")
	}
	if err := s.apply(settings); err != nil {
		return err
	}
	if err := s.framer.WriteSettingsAck(); err != nil {
		return err
	}
	block, err := tunnelHeaderBlock(req)
	if err != nil {
		return err
	}
	return s.writeHeaders(block)
}

func tunnelHeaderBlock(req *http.Request) ([]byte, error) {
	authority := req.Host
	if authority == "" {
		authority = req.URL.Host
	}
	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: req.Header.Get(":protocol")},
		{Name: ":scheme", Value: scheme},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: req.URL.RequestURI()},
	}
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		if tunnelSkippedHeaders[lower] || strings.HasPrefix(lower, ":") {
			continue
		}
		for _, value := range values {
			fields = append(fields, hpack.HeaderField{Name: lower, Value: value})
		}
	}
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			return nil, err
		}
	}
	return block.Bytes(), nil
}

func (s *tunnelStream) writeHeaders(block []byte) error {
	limit := int(s.maxFrame)
	first := block[:min(len(block), limit)]
	block = block[len(first):]
	err := s.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: tunnelStreamID, BlockFragment: first, EndHeaders: len(block) == 0})
	for err == nil && len(block) > 0 {
		next := block[:min(len(block), limit)]
		block = block[len(next):]
		err = s.framer.WriteContinuation(tunnelStreamID, len(block) == 0, next)
	}
	return err
}

func (s *tunnelStream) apply(settings *http2.SettingsFrame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return settings.ForeachSetting(func(setting http2.Setting) error {
		if err := setting.Valid(); err != nil {
			return err
		}
		switch setting.ID {
		case http2.SettingInitialWindowSize:
			s.sendStream += int64(setting.Val) - 65535
		case http2.SettingMaxFrameSize:
			s.maxFrame = setting.Val
		}
		return nil
	})
}

func (s *tunnelStream) read() {
	for {
		frame, err := s.framer.ReadFrame()
		if err == nil {
			err = s.handle(frame)
		}
		if err != nil {
			s.fail(err)
			return
		}
	}
}

func (s *tunnelStream) handle(frame http2.Frame) error {
	switch f := frame.(type) {
	case *http2.MetaHeadersFrame:
		return s.headers(f)
	case *http2.DataFrame:
		return s.data(f)
	case *http2.WindowUpdateFrame:
		s.mu.Lock()
		if f.StreamID == 0 {
			s.sendConn += int64(f.Increment)
		} else {
			s.sendStream += int64(f.Increment)
		}
		s.cond.Broadcast()
		s.mu.Unlock()
	case *http2.SettingsFrame:
		if f.IsAck() {
			return nil
		}
		if err := s.apply(f); err != nil {
			return err
		}
		s.mu.Lock()
		s.cond.Broadcast()
		s.mu.Unlock()
		return s.write(s.framer.WriteSettingsAck)
	case *http2.PingFrame:
		if !f.IsAck() {
			return s.write(func() error { return s.framer.WritePing(true, f.Data) })
		}
	case *http2.RSTStreamFrame:
		return fmt.Errorf("upstream reset the tunnel: %v", f.ErrCode)
	case *http2.GoAwayFrame:
		if f.LastStreamID < tunnelStreamID {
			return fmt.Errorf("upstream refused the tunnel: %v", f.ErrCode)
		}
	}
	return nil
}

func (s *tunnelStream) headers(f *http2.MetaHeadersFrame) error {
	if f.StreamID != tunnelStreamID {
		return fmt.Errorf("upstream answered on stream %d", f.StreamID)
	}
	s.mu.Lock()
	answered := s.answered
	s.mu.Unlock()
	if answered {
		s.finish()
		return nil
	}
	status, err := strconv.Atoi(f.PseudoValue("status"))
	if err != nil {
		return errors.New("upstream answered without a status")
	}
	if status < 200 {
		return nil
	}
	header := make(http.Header, len(f.RegularFields()))
	for _, field := range f.RegularFields() {
		header.Add(http.CanonicalHeaderKey(field.Name), field.Value)
	}
	s.mu.Lock()
	s.answered = true
	s.mu.Unlock()
	s.answer <- &http.Response{
		Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), StatusCode: status,
		Proto: "HTTP/2.0", ProtoMajor: 2, Header: header, Body: s, ContentLength: -1,
	}
	if f.StreamEnded() {
		s.finish()
	}
	return nil
}

func (s *tunnelStream) data(f *http2.DataFrame) error {
	if f.StreamID != tunnelStreamID {
		return fmt.Errorf("upstream sent data on stream %d", f.StreamID)
	}
	s.mu.Lock()
	if !s.answered || s.recvEnd {
		s.mu.Unlock()
		return errors.New("upstream sent data outside the tunnel response")
	}
	s.recv = append(s.recv, f.Data()...)
	overrun := len(s.recv) > tunnelWindow
	s.recvEnd = f.StreamEnded()
	s.cond.Broadcast()
	s.mu.Unlock()
	if overrun {
		return errors.New("upstream overran the tunnel flow-control window")
	}
	if padding := int(f.Header().Length) - len(f.Data()); padding > 0 {
		return s.credit(padding)
	}
	return nil
}

func (s *tunnelStream) finish() {
	s.mu.Lock()
	s.recvEnd = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *tunnelStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	for len(s.recv) == 0 && !s.recvEnd && s.err == nil {
		s.cond.Wait()
	}
	if len(s.recv) == 0 {
		defer s.mu.Unlock()
		if s.recvEnd {
			return 0, io.EOF
		}
		return 0, s.err
	}
	n := copy(p, s.recv)
	s.recv = s.recv[n:]
	ended := s.recvEnd
	s.mu.Unlock()
	if !ended {
		_ = s.credit(n)
	}
	return n, nil
}

func (s *tunnelStream) credit(n int) error {
	return s.write(func() error {
		if err := s.framer.WriteWindowUpdate(0, uint32(n)); err != nil {
			return err
		}
		return s.framer.WriteWindowUpdate(tunnelStreamID, uint32(n))
	})
}

func (s *tunnelStream) send(body io.ReadCloser) {
	if body == nil {
		_ = s.write(func() error { return s.framer.WriteData(tunnelStreamID, true, nil) })
		return
	}
	defer body.Close()
	buffer := make([]byte, 16<<10)
	for {
		n, err := body.Read(buffer)
		for chunk := buffer[:n]; len(chunk) > 0; {
			size, ok := s.reserve(len(chunk))
			if !ok {
				return
			}
			if s.write(func() error { return s.framer.WriteData(tunnelStreamID, false, chunk[:size]) }) != nil {
				return
			}
			chunk = chunk[size:]
		}
		if errors.Is(err, io.EOF) {
			_ = s.write(func() error { return s.framer.WriteData(tunnelStreamID, true, nil) })
			return
		}
		if err != nil {
			_ = s.write(func() error { return s.framer.WriteRSTStream(tunnelStreamID, http2.ErrCodeCancel) })
			s.fail(err)
			return
		}
	}
}

func (s *tunnelStream) reserve(want int) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for (s.sendConn <= 0 || s.sendStream <= 0) && s.err == nil {
		s.cond.Wait()
	}
	if s.err != nil {
		return 0, false
	}
	size := int(min(int64(want), s.sendConn, s.sendStream, int64(s.maxFrame)))
	s.sendConn -= int64(size)
	s.sendStream -= int64(size)
	return size, true
}

func (s *tunnelStream) write(frame func() error) error {
	s.wmu.Lock()
	err := frame()
	s.wmu.Unlock()
	if err != nil {
		s.fail(err)
	}
	return err
}

func (s *tunnelStream) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
		close(s.failed)
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	_ = s.conn.Close()
}

func (s *tunnelStream) failure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *tunnelStream) Close() error {
	s.fail(errTunnelClosed)
	s.stop()
	return nil
}
