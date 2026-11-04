package cli

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/VictoriaMetrics/metrics"
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
	token := "observe-test-bearer-token-not-in-any-payload"
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
