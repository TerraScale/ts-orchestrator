package edge

import (
	"context"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
)

// A proxy error named only the host and the error. On gru 2026-10-27
// 23:02-23:11Z signed-in dashboard requests waited 30 s for response headers
// during a rollout and nothing showed which task held them. backendTrace
// records, per client request, the local connection the edge used so the
// error log can name the backend, the task the handoff forwarder spliced it
// to, the wait for a connection and how long the request ran.
type backendTrace struct {
	start time.Time
	mu    sync.Mutex
	asked time.Time // GetConn
	got   time.Time // GotConn
	info  httptrace.GotConnInfo
}

type backendTraceKey struct{}

// withBackendTrace starts the trace for a client request.
func withBackendTrace(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), backendTraceKey{}, &backendTrace{start: time.Now()}))
}

// traceBackend records the connection an outbound request gets.
func traceBackend(r *http.Request) *http.Request {
	trace, ok := r.Context().Value(backendTraceKey{}).(*backendTrace)
	if !ok {
		return r
	}
	return r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
		GetConn: func(string) {
			trace.mu.Lock()
			trace.asked = time.Now()
			trace.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			trace.mu.Lock()
			trace.got, trace.info = time.Now(), info
			trace.mu.Unlock()
		},
	}))
}

// proxyErrorContext describes a failed request without its query, body or
// credentials: only whether it carried any.
func proxyErrorContext(r *http.Request) []any {
	fields := []any{"method", r.Method, "route", firstSegment(r.URL.Path),
		"signed_in", r.Header.Get("Authorization") != "" || len(r.Cookies()) != 0}
	trace, ok := r.Context().Value(backendTraceKey{}).(*backendTrace)
	if !ok {
		return fields
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	fields = append(fields, "elapsed_ms", time.Since(trace.start).Milliseconds())
	if trace.got.IsZero() {
		return append(fields, "backend", "no connection")
	}
	fields = append(fields, "conn_wait_ms", trace.got.Sub(trace.asked).Milliseconds(), "conn_reused", trace.info.Reused)
	if trace.info.WasIdle {
		fields = append(fields, "conn_idle_ms", trace.info.IdleTime.Milliseconds())
	}
	conn := trace.info.Conn
	if conn == nil {
		return fields
	}
	fields = append(fields, "backend", conn.RemoteAddr().String())
	if remote, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		fields = append(fields, "backend_held", handoff.Held(uint16(remote.Port)))
	}
	if local, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		if target, ok := handoff.Spliced(uint16(local.Port)); ok {
			fields = append(fields, "task_port", strconv.Itoa(int(target)))
		}
	}
	return fields
}

// firstSegment keeps a path's first segment; later ones can carry tokens.
func firstSegment(path string) string {
	first, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	return "/" + first
}
