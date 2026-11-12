package edge

import (
	"bufio"
	"net"
	"net/http"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func countResponses(protocol string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := &responseWriter{ResponseWriter: w, protocol: protocol}
		handler.ServeHTTP(response, r)
		if !response.started {
			response.WriteHeader(http.StatusOK)
		}
	})
}

type responseWriter struct {
	http.ResponseWriter
	protocol string
	started  bool
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseWriter) record(code int) {
	if !w.started && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.started = true
		observability.RecordEdgeResponse(w.protocol, code)
	}
}

func (w *responseWriter) WriteHeader(code int) {
	w.ResponseWriter.WriteHeader(code)
	w.record(code)
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.started {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *responseWriter) FlushError() error {
	if !w.started {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *responseWriter) Flush() { _ = w.FlushError() }

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffered, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.record(http.StatusSwitchingProtocols)
	}
	return conn, buffered, err
}
