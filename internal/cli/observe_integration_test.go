package cli

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/VictoriaMetrics/metrics"
	natserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

type observeFixture struct {
	server           *observability.Server
	http             *httptest.Server
	tokenFile, token string
	history          *observability.History
}

func newObserveFixture(t *testing.T) *observeFixture {
	t.Helper()
	registry := observability.NewRegistry(false)
	set := metrics.NewSet()
	set.NewCounter(`ts_orch_cli_requests_total{service="controller"}`).Add(3)
	registry.Register(set)
	health := new(observability.Health)
	collector, err := observability.NewCollector(observability.CollectorConfig{Cell: "gru-1", Member: "controller-a", Role: "controller", Registry: registry, Health: health})
	if err != nil {
		t.Fatal(err)
	}
	bus := observability.NewEventBus(8)
	bus.Publish(observability.Event{Level: "INFO", Component: "release", Message: "release observed", Attrs: map[string]string{"operation_id": "op-1"}})
	token := strings.Repeat("a", 32)
	server, err := observability.NewTokenServer(observability.Config{ListenAddress: "127.0.0.1:9463"}, token, observability.ServerDeps{Registry: registry, Health: health, Snapshots: collector, Events: bus})
	if err != nil {
		t.Fatal(err)
	}
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(time.Now(), []observability.Sample{{Metric: "ts_orch_cli_requests_total", Labels: observability.L("service", "controller"), Counter: true, Value: 3}})
	server.HandleMetricHistory(history)
	httpServer := httptest.NewServer(server)
	t.Cleanup(httpServer.Close)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	return &observeFixture{server, httpServer, file, token, history}
}

func (f *observeFixture) run(t *testing.T, view string, flags ...string) (string, error) {
	t.Helper()
	var output bytes.Buffer
	args := append([]string{"observe", view, "--url", f.http.URL, "--token-file", f.tokenFile}, flags...)
	err := Run(t.Context(), args, &output)
	if strings.Contains(output.String(), f.token) || (err != nil && strings.Contains(err.Error(), f.token)) {
		t.Fatal("observe disclosed bearer token")
	}
	return output.String(), err
}

func TestObserveRealAuthenticatedViews(t *testing.T) {
	f := newObserveFixture(t)
	for _, test := range []struct {
		view  string
		flags []string
		want  string
	}{
		{"snapshot", nil, "controller-a"},
		{"events", nil, "op-1"},
		{"history", []string{"--metric", "ts_orch_cli_requests_total", "--label", "service=controller"}, "controller"},
		{"metrics", []string{"--search", "cli_requests"}, "ts_orch_cli_requests_total"},
	} {
		t.Run(test.view, func(t *testing.T) {
			output, err := f.run(t, test.view, test.flags...)
			if err != nil || !strings.Contains(output, test.want) {
				t.Fatalf("output %q error %v", output, err)
			}
			args := append(append([]string{}, test.flags...), "--format", "json")
			output, err = f.run(t, test.view, args...)
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Version int            `json:"version"`
				View    string         `json:"view"`
				Partial bool           `json:"partial"`
				Data    map[string]any `json:"data"`
			}
			if test.view == "events" {
				var document map[string]any
				if err := json.Unmarshal([]byte(output), &document); err != nil || document["view"] != "events" {
					t.Fatalf("event JSON %q: %v", output, err)
				}
				return
			}
			if err := json.Unmarshal([]byte(output), &envelope); err != nil || envelope.Version != 1 || envelope.View != test.view || envelope.Partial {
				t.Fatalf("versioned output %q: %v", output, err)
			}
		})
	}
	response, err := http.Get(f.http.URL + "/v1/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("unauthenticated API status %d", response.StatusCode)
	}
	if err := os.WriteFile(f.tokenFile, []byte(strings.Repeat("b", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := f.run(t, "snapshot")
	if err == nil || !strings.Contains(err.Error(), "authentication denied") || output != "" {
		t.Fatalf("auth output %q error %v", output, err)
	}
}

func TestObserveRealHistoryTruncation(t *testing.T) {
	f := newObserveFixture(t)
	f.history.Append(time.Now().Add(-time.Minute), []observability.Sample{{Metric: "ts_orch_cli_requests_total", Labels: observability.L("service", "host"), Counter: true, Value: 5}})
	output, err := f.run(t, "history", "--metric", "ts_orch_cli_requests_total", "--max", "1", "--format", "json")
	if err == nil || !strings.Contains(err.Error(), "partial") || !strings.Contains(output, `"truncated": true`) || !strings.Contains(output, `"partial": true`) {
		t.Fatalf("truncated output %q error %v", output, err)
	}
	output, err = f.run(t, "history", "--metric", "ts_orch_cli_requests_total", "--range", "-1h")
	if err == nil || output != "" {
		t.Fatalf("invalid range output %q error %v", output, err)
	}
}

func TestObserveRealHistorySeriesCoverage(t *testing.T) {
	for _, coverage := range []string{"stale", "gaps"} {
		t.Run(coverage, func(t *testing.T) {
			f := newObserveFixture(t)
			olderMember := "fresh"
			if coverage == "stale" {
				olderMember = "stale"
			}
			const metric = "cli_history_coverage"
			now := time.Now()
			f.history.Append(now.Add(-time.Minute), []observability.Sample{{Metric: metric,
				Labels: observability.L("member", olderMember), Value: 1}})
			f.history.Append(now, []observability.Sample{{Metric: metric,
				Labels: observability.L("member", "fresh"), Value: 2}})
			for _, format := range []string{"table", "json"} {
				t.Run(format, func(t *testing.T) {
					output, runErr := f.run(t, "history", "--metric", metric, "--tier", "raw", "--format", format)
					if runErr == nil || !strings.Contains(runErr.Error(), "partial") {
						t.Fatalf("%s coverage reported complete: output %q, error %v", coverage, output, runErr)
					}
					if format == "table" {
						fields := strings.Join(strings.Fields(output), " ")
						if !strings.Contains(fields, "STATE available") || !strings.Contains(fields, strings.ToUpper(coverage)+" true") {
							t.Fatalf("missing %s coverage in table: %q", coverage, output)
						}
						return
					}
					var envelope struct {
						Partial bool                         `json:"partial"`
						Data    observability.CatalogHistory `json:"data"`
					}
					if err := json.Unmarshal([]byte(output), &envelope); err != nil || !envelope.Partial || envelope.Data.State != "available" {
						t.Fatalf("partial history envelope %q: %v", output, err)
					}
					found := false
					for _, series := range envelope.Data.Series {
						found = found || coverage == "stale" && series.Stale || coverage == "gaps" && series.Gaps
					}
					if !found {
						t.Fatalf("missing %s coverage in history: %+v", coverage, envelope.Data)
					}
				})
			}
		})
	}
}

func TestObserveRealAPIErrorsAndBounds(t *testing.T) {
	f := newObserveFixture(t)
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"upstream", 503, f.token, "HTTP 503"},
		{"invalid-json", 200, "{", "invalid member snapshot JSON"},
		{"empty", 200, "null", "empty observation"},
		{"trailing-json", 200, `{"member":"one"} {}`, "invalid member snapshot JSON"},
		{"oversized", 200, strings.Repeat("x", (8<<20)+1), "exceeds 8 MiB"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f.server.Handle("GET /v1/test-"+test.name, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(test.status); io.WriteString(w, test.body) }))
			// Keep real API authentication while directing the transport to fault responses.
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.URL.Path = "/v1/test-" + test.name
				f.server.ServeHTTP(w, r)
			}))
			defer proxy.Close()
			previous := f.http
			f.http = proxy
			defer func() { f.http = previous }()
			output, err := f.run(t, "snapshot")
			if err == nil || !strings.Contains(err.Error(), test.want) || output != "" {
				t.Fatalf("output %q error %v", output, err)
			}
		})
	}
	t.Run("redirect-no-credential-forward", func(t *testing.T) {
		hits := 0
		destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(200) }))
		defer destination.Close()
		f.server.Handle("GET /v1/test-redirect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = "/v1/test-redirect"
			f.server.ServeHTTP(w, r)
		}))
		defer proxy.Close()
		var out bytes.Buffer
		err := Run(t.Context(), []string{"observe", "events", "--url", proxy.URL, "--token-file", f.tokenFile}, &out)
		if err == nil || hits != 0 || !strings.Contains(err.Error(), "HTTP 302") {
			t.Fatalf("redirect hits %d error %v", hits, err)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		f.server.Handle("GET /v1/test-slow", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.URL.Path = "/v1/test-slow"; f.server.ServeHTTP(w, r) }))
		defer proxy.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
		defer cancel()
		var out bytes.Buffer
		err := Run(ctx, []string{"observe", "events", "--url", proxy.URL, "--token-file", f.tokenFile}, &out)
		if !errors.Is(err, context.DeadlineExceeded) || out.Len() != 0 {
			t.Fatalf("deadline error %v output %q", err, out.String())
		}
	})
}

func TestObserveRealClusterMissingMember(t *testing.T) {
	f := newObserveFixture(t)
	broker, err := natserver.NewServer(&natserver.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(broker.Shutdown)
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	conn, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	aggregator, err := observability.NewAggregator(conn, "gru-1", []string{"controller-a", "controller-b"}, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	f.server.HandleCluster(aggregator)
	output, err := f.run(t, "cluster", "--format", "json")
	if err == nil || !strings.Contains(output, `"partial": true`) || !strings.Contains(output, "controller-b") {
		t.Fatalf("missing-member output %q error %v", output, err)
	}
}

func TestObservePrivateTokenAndTargetValidation(t *testing.T) {
	f := newObserveFixture(t)
	for _, args := range [][]string{{"--url", f.http.URL}, {"--token-file", f.tokenFile}} {
		var out bytes.Buffer
		err := Run(t.Context(), append([]string{"observe", "snapshot"}, args...), &out)
		if err == nil || !strings.Contains(err.Error(), "requires --url and --token-file together") || out.Len() != 0 {
			t.Fatalf("partial diagnostic access attempted automatic authorization: %s %v", out.String(), err)
		}
	}
	if err := os.Chmod(f.tokenFile, 0644); err != nil {
		t.Fatal(err)
	}
	output, err := f.run(t, "snapshot")
	if err == nil || !strings.Contains(err.Error(), "private regular file") || output != "" {
		t.Fatalf("public-token output %q error %v", output, err)
	}
	if err := os.Chmod(f.tokenFile, 0600); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"http://public.example", "https://user:secret@example.com", "https://example.com/prefix", "https://example.com?secret=bad"} {
		var out bytes.Buffer
		err := Run(t.Context(), []string{"observe", "snapshot", "--url", origin, "--token-file", f.tokenFile}, &out)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "secret") {
			t.Fatalf("target %q error %v", origin, err)
		}
	}
}
