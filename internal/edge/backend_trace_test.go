package edge

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
)

// A proxy error names the forwarder's task port, the connection's reuse and
// whether the client was signed in, never its path tail, query or cookies.
func TestProxyErrorContextNamesTheTask(t *testing.T) {
	task := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer task.Close()
	taskPort := task.Listener.Addr().(*net.TCPAddr).Port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	service := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	handoff.Serve(uint16(service), uint16(taskPort))
	defer handoff.Unserve(uint16(service), uint16(taskPort))

	transport := &http.Transport{DialContext: dialHandoff}
	defer transport.CloseIdleConnections()
	in := httptest.NewRequest(http.MethodGet, "https://dash.example/projects/secret-token?code=x", nil)
	in.AddCookie(&http.Cookie{Name: "session", Value: "private"})
	in = withBackendTrace(in)
	out, _ := http.NewRequestWithContext(in.Context(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", service), nil)
	resp, err := transport.RoundTrip(traceBackend(out))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	fields := map[string]any{}
	context := proxyErrorContext(in)
	for i := 0; i+1 < len(context); i += 2 {
		fields[context[i].(string)] = context[i+1]
	}
	if fields["route"] != "/projects" || fields["signed_in"] != true || fields["task_port"] != strconv.Itoa(taskPort) ||
		fields["backend"] != net.JoinHostPort("127.0.0.1", strconv.Itoa(service)) || fields["conn_reused"] != false {
		t.Fatalf("context = %v", fields)
	}
	for _, value := range fields {
		if s, ok := value.(string); ok && (s == "private" || s == "secret-token") {
			t.Fatalf("logged a credential or path tail: %v", fields)
		}
	}
}
