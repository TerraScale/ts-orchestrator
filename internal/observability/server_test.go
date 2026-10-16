package observability

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VictoriaMetrics/metrics"
)

func TestServerValidatesPrivateListenersAndTokenFiles(t *testing.T) {
	t.Parallel()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(strings.Repeat("t", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := ServerDeps{Registry: NewRegistry(false), Health: new(Health)}
	for _, address := range []string{"127.0.0.1:9464", "[::1]:9464", "10.0.1.5:9464", "172.16.4.2:9464", "192.168.1.10:9464", "10.200.106.253:9464", "[fd00::1]:9464"} {
		service, err := NewServer(Config{ListenAddress: address, BearerTokenFile: tokenFile}, deps)
		if err != nil {
			t.Fatalf("NewServer(%q): %v", address, err)
		}
		request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		request.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 40))
		response := httptest.NewRecorder()
		service.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("listener %q metrics = %d", address, response.Code)
		}
	}
	service, err := NewServer(Config{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"0.0.0.0:9464", "[::]:9464", ":9464", "localhost:9464", "8.8.8.8:9464", "169.254.1.1:9464", "224.0.0.1:9464", "127.0.0.1:0", "127.0.0.1", "[fe80::1%eth0]:9464", "127.000.0.1:9464", "[::ffff:8.8.8.8]:9464", "100.90.12.3:9464", "off"} {
		if _, err := service.Start(t.Context(), Config{ListenAddress: address}); err == nil {
			service.Close()
			t.Fatalf("Start accepted %q", address)
		}
	}
	for _, config := range []Config{{ListenAddress: "10.0.0.4:9464"}, {TLSCertFile: "/cert"}, {LogFormat: "xml"}, {LogLevel: "trace"}} {
		if _, err := service.Start(t.Context(), config); err == nil {
			service.Close()
			t.Fatalf("Start accepted %+v", config)
		}
	}
}

func TestServerRoutesAndBearerToken(t *testing.T) {
	t.Parallel()
	tokenFile := filepath.Join(t.TempDir(), "token")
	token := strings.Repeat("t", 40)
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(false)
	set := metrics.NewSet()
	set.NewCounter(MetricPrefix + "test_total").Add(3)
	registry.Register(set)
	health := new(Health)
	ready := false
	health.Add(Check{Name: "nats", Run: func(context.Context) (bool, string) { return ready, "not connected" }})
	bus := NewEventBus(8)
	bus.Publish(Event{Message: "hello"})
	server, err := NewServer(Config{ListenAddress: "10.0.0.4:9464", BearerTokenFile: tokenFile},
		ServerDeps{Registry: registry, Health: health, Events: bus})
	if err != nil {
		t.Fatal(err)
	}
	request := func(path, authorization string, headers ...string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		for index := 0; index+1 < len(headers); index += 2 {
			req.Header.Set(headers[index], headers[index+1])
		}
		server.ServeHTTP(recorder, req)
		return recorder
	}
	if response := request("/healthz", ""); response.Code != http.StatusOK {
		t.Fatalf("/healthz = %d", response.Code)
	}
	if response := request("/readyz", ""); response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), "nats failing: not connected") {
		t.Fatalf("/readyz = %d %q", response.Code, response.Body.String())
	}
	ready = true
	if response := request("/readyz", ""); response.Code != http.StatusOK {
		t.Fatalf("ready /readyz = %d", response.Code)
	}
	if response := request("/metrics", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /metrics = %d", response.Code)
	}
	if response := request("/metrics", "Bearer wrong"); response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token /metrics = %d", response.Code)
	}
	response := request("/metrics", "Bearer "+token)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "ts_orch_test_total 3") {
		t.Fatalf("/metrics = %d %q", response.Code, response.Body.String())
	}
	if response := request("/metrics", "Bearer "+token, "X-Forwarded-For", "1.2.3.4"); response.Code != http.StatusBadRequest {
		t.Fatalf("proxied /metrics = %d", response.Code)
	}
	response = request("/v1/events?limit=5", "Bearer "+token)
	var events []Event
	if err := json.Unmarshal(response.Body.Bytes(), &events); err != nil || len(events) != 1 || events[0].Message != "hello" {
		t.Fatalf("/v1/events = %q, %v", response.Body.String(), err)
	}
	if response := request("/v1/cluster", "Bearer "+token); response.Code != http.StatusNotFound {
		t.Fatalf("unconfigured /v1/cluster = %d", response.Code)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if recorder.Code != http.StatusMethodNotAllowed && recorder.Code != http.StatusUnauthorized {
		t.Fatalf("POST /metrics = %d", recorder.Code)
	}
}

func TestServerRejectsSharedTokenFile(t *testing.T) {
	t.Parallel()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(strings.Repeat("t", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := NewServer(Config{ListenAddress: "10.0.0.4:9464", BearerTokenFile: tokenFile},
		ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
	if err == nil {
		t.Fatal("world-readable bearer token was accepted")
	}
}

func TestServerStartServesOnLoopback(t *testing.T) {
	t.Parallel()
	health := new(Health)
	health.Add(Check{Name: "always", Run: func(context.Context) (bool, string) { return true, "" }})
	server, err := NewServer(Config{}, ServerDeps{Registry: NewRegistry(true), Health: health})
	if err != nil {
		t.Fatal(err)
	}
	// Bind an ephemeral loopback port through the same validated path by
	// reserving one first.
	probe := httptest.NewServer(http.NotFoundHandler())
	address := strings.TrimPrefix(probe.URL, "http://")
	probe.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result, err := server.Start(ctx, Config{ListenAddress: address})
	if err != nil {
		t.Fatalf("start loopback listener: %v", err)
	}
	response, err := http.Get("http://" + server.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "go_goroutines") {
		t.Fatalf("/metrics = %d, process metrics missing", response.StatusCode)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("serve result = %v", err)
	}
}

// A server built without a token must not be widened onto a private address
// by a different Start config.
func TestServerStartRefusesTokenlessNetworkAddress(t *testing.T) {
	t.Parallel()
	server, err := NewServer(Config{}, ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Start(t.Context(), Config{ListenAddress: "10.0.0.1:9464"}); err == nil ||
		!strings.Contains(err.Error(), "bearer_token_file") {
		_ = server.Close()
		t.Fatalf("Start(tokenless private address) error = %v", err)
	}
}

// A tokenless loopback listener is reachable from a DNS-rebinding page under
// an attacker hostname, so every route, not only the dashboard's, requires an
// IP literal or localhost as the Host.
func TestTokenlessServerRefusesHostnamesOnEveryRoute(t *testing.T) {
	t.Parallel()
	server, err := NewServer(Config{}, ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	server.Handle("GET /v1/extra", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	for _, path := range []string{"/metrics", "/healthz", "/v1/extra"} {
		for host, want := range map[string]int{
			"rebind.attacker.example:9464": http.StatusMisdirectedRequest,
			"127.0.0.1:9464":               http.StatusOK,
			"[::1]:9464":                   http.StatusOK,
			"localhost:9464":               http.StatusOK,
		} {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Host = host
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, request)
			if recorder.Code != want {
				t.Fatalf("GET %s with Host %q = %d, want %d", path, host, recorder.Code, want)
			}
		}
	}
}
