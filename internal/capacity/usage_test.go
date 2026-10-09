package capacity

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func fixture(t *testing.T) (*Store, time.Time, time.Time) {
	return fixtureWithLimit(t, 4096)
}

func fixtureWithLimit(t *testing.T, maxSeries int) (*Store, time.Time, time.Time) {
	t.Helper()
	s := NewStore("gru")
	s.History = observability.NewHistory(observability.HistoryConfig{Interval: 5 * time.Second, MaxSeries: maxSeries})
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

func TestRecoveredWindowDoesNotInheritEarlierOverflow(t *testing.T) {
	s, from, to := fixtureWithLimit(t, 32)
	s.History.Append(from, []observability.Sample{{Metric: "capacity_cpu_usage", Labels: observability.L("node", "dropped"), Value: 1}})
	lost, err := s.Query(from, to, nil)
	if err != nil || !lost.Truncated || lost.Complete {
		t.Fatalf("lost coverage was hidden: %+v %v", lost, err)
	}
	healthyFrom := from.Truncate(time.Minute).Add(time.Minute)
	recovered, err := s.Query(healthyFrom, to, nil)
	if err != nil || recovered.Truncated || !recovered.Complete || s.History.Stats().Dropped == 0 {
		t.Fatalf("earlier overflow poisoned healthy coverage: %+v %v", recovered, err)
	}
	// A later drop must not conceal the earlier queried loss.
	s.History.Append(to, []observability.Sample{{Metric: "capacity_cpu_usage", Labels: observability.L("node", "another"), Value: 1}})
	lost, err = s.Query(from, healthyFrom, nil)
	if err != nil || !lost.Truncated {
		t.Fatalf("only the latest drop was retained: %+v %v", lost, err)
	}
}

func TestQueryClosesOwnedConnectionsAndPreservesCallerTransport(t *testing.T) {
	_, from, to := fixture(t)
	closed := make(chan struct{}, 4)
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Usage{Region: "gru", From: from, To: to, Complete: true})
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	server.Start()
	defer server.Close()
	client := Client{URLs: []string{server.URL}, Token: strings.Repeat("a", 32)}
	if _, err := client.Query(t.Context(), "gru", from, to); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("query retained an owned idle connection")
	}
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client.HTTP = &http.Client{Transport: transport}
	for range 2 {
		if _, err := client.Query(t.Context(), "gru", from, to); err != nil {
			t.Fatal(err)
		}
	}
	if connections.Load() != 2 {
		t.Fatalf("caller transport did not reuse its connection: %d", connections.Load())
	}
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
	server.HandleAuthenticated("GET /v1/usage", s.Handler(func(context.Context, time.Time, time.Time) ([]string, error) { return []string{"a", "b"}, nil }))
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

func TestAllocatedRequestsSurviveMissingMeasurements(t *testing.T) {
	for _, known := range []bool{true, false} {
		t.Run(map[bool]string{true: "known request", false: "unknown request"}[known], func(t *testing.T) {
			s := NewStore("gru")
			cpu, memory := 0.25, 0.5
			report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPUCores: 4, MemoryBytes: 8192, CPU: &cpu, Memory: &memory}, Roles: []hostload.RoleUsage{{Role: "terrabase"}, {Role: "api"}}}
			requests := map[string]hostload.Request{"terrabase": {CPUCores: 2, MemoryBytes: 1024}}
			if known {
				requests["api"] = hostload.Request{CPUCores: 1, MemoryBytes: 512}
			}
			if err := s.Record(hostload.Origin{Cell: "gru", Node: "a", Environment: "production"}, report, requests); err != nil {
				t.Fatal(err)
			}
			to := time.Now().UTC().Add(time.Second)
			result, err := s.Query(to.Add(-10*time.Second), to, []string{"a", "a/terrabase", "a/api"})
			if err != nil || len(result.Nodes) != 1 || result.Complete || len(result.Missing) != 2 {
				t.Fatalf("missing measurements were concealed: %+v %v", result, err)
			}
			node := result.Nodes[0]
			if known {
				if node.CPU.Request == nil || node.CPU.Request.Mean != 3 || node.Memory.Request == nil || node.Memory.Request.Mean != 1536 {
					t.Fatalf("allocated reservations disappeared: %+v", node)
				}
			} else if node.CPU.Request != nil || node.Memory.Request != nil {
				t.Fatalf("partial reservations reported as a node total: %+v", node)
			}
			for _, replica := range result.Replicas {
				if replica.CPU.Usage != nil || replica.Memory.Usage != nil || replica.CPU.Headroom != nil || replica.Memory.Headroom != nil {
					t.Fatalf("missing measurements became spare capacity: %+v", replica)
				}
			}
		})
	}
}
