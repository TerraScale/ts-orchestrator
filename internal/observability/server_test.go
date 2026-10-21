package observability

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
