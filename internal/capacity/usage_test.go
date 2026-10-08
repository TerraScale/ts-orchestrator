package capacity

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func fixture(t *testing.T) (*Store, time.Time, time.Time) {
	t.Helper()
	s := NewStore("gru")
	to := time.Now().UTC().Truncate(5 * time.Second).Add(-5 * time.Second)
	from := to.Add(-2 * time.Minute)
	for _, node := range []string{"a", "b"} {
		for at := from; !at.After(to); at = at.Add(5 * time.Second) {
			var samples []observability.Sample
			for _, service := range []string{"", "terrabase"} {
				for metric, value := range map[string]float64{"cpu_usage": 1, "cpu_request": 2, "cpu_limit": 4, "cpu_headroom": 3, "memory_usage": 100, "memory_request": 200, "memory_limit": 400, "memory_headroom": 300} {
					samples = append(samples, observability.Sample{Metric: "capacity_" + metric, Labels: observability.L("node", node, "service", service, "environment", "production"), Value: value})
				}
			}
			s.History.Append(at, samples)
		}
	}
	return s, from, to
}

func TestWindowTotalsAndMissingData(t *testing.T) {
	s, from, to := fixture(t)
	result, err := s.Query(from, to, []string{"a", "b", "a/terrabase", "b/terrabase"})
	if err != nil || !result.Complete || len(result.Nodes) != 2 || len(result.Replicas) != 2 || len(result.Services) != 1 {
		t.Fatalf("window: %+v %v", result, err)
	}
	service := result.Services[0]
	if service.CPU.Usage.Mean != 2 || service.CPU.Limit.Min != 8 || service.Memory.Headroom.Min != 600 {
		t.Fatalf("totals: %+v", service)
	}
	result, err = s.Query(from, to, []string{"missing", "a/ts-auth"})
	if err != nil || result.Complete || len(result.Missing) != 2 {
		t.Fatalf("missing data claimed complete: %+v %v", result, err)
	}
	var out bytes.Buffer
	if err := WriteTable(&out, result); err != nil || !strings.Contains(out.String(), "production/terrabase") {
		t.Fatalf("table: %s %v", out.String(), err)
	}
	if _, err := s.Query(from.Add(-2*time.Hour), to, nil); err == nil {
		t.Fatal("accepted expired window")
	}
}

func TestGapAndUnknownCannotClaimComplete(t *testing.T) {
	to := time.Now().UTC().Add(-time.Second)
	from := to.Add(-10 * time.Minute)
	points := []observability.Point{{Time: from, Value: 1, Min: 1, Max: 1}, {Time: to, Value: 2, Min: 2, Max: 2}}
	if summarize(points, from, to).Complete {
		t.Fatal("two distant points claimed complete")
	}
	if rowComplete(Row{}) {
		t.Fatal("unknown usage claimed complete")
	}
}

func TestAuthenticatedAPIAndRegionalClient(t *testing.T) {
	s, from, to := fixture(t)
	token := strings.Repeat("a", 32)
	server, err := observability.NewTokenServer(observability.Config{ListenAddress: "127.0.0.1:9463"}, token, observability.ServerDeps{Registry: observability.NewRegistry(false), Health: new(observability.Health)})
	if err != nil {
		t.Fatal(err)
	}
	server.HandleAuthenticated("GET /v1/usage", s.Handler(func(context.Context) ([]string, error) { return []string{"a", "b"}, nil }))
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	response, err := http.Get(httpServer.URL + "/v1/usage")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("unauthenticated status %d", response.StatusCode)
	}
	result, err := (Client{URLs: []string{httpServer.URL}, Token: token}).Query(t.Context(), "gru", from, to)
	if err != nil || !result.Complete {
		t.Fatalf("authenticated query: %+v %v", result, err)
	}
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded.String(), token) {
		t.Fatal("token leaked in usage")
	}
	if _, err := (Client{URLs: []string{httpServer.URL}, Token: token}).Query(t.Context(), "sfo", from, to); err == nil {
		t.Fatal("accepted mismatched region")
	}
}

func TestRecordRejectsSpoofedRegionAndThrottles(t *testing.T) {
	s := NewStore("gru")
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion}
	if err := s.Record(hostload.Origin{Cell: "sfo", Node: "a"}, report, nil); err == nil {
		t.Fatal("accepted cross-region report")
	}
	origin := hostload.Origin{Cell: "gru", Node: "a"}
	if err := s.Record(origin, report, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(origin, report, nil); err != hostload.ErrTooFrequent {
		t.Fatalf("unbounded reports: %v", err)
	}
}
