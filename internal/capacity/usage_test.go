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

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
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
	server.HandleAuthenticated("GET /v1/usage", s.Handler(func(context.Context, time.Time, time.Time) ([]hostload.UsageInterval, error) {
		return fullWindowInventory(from, to, "production", "a", "b", "a/terrabase", "b/terrabase"), nil
	}))
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
	if len(result.Nodes) != 2 || len(result.Replicas) != 2 || len(result.Services) != 1 {
		t.Fatalf("window: %+v", result)
	}
	service := result.Services[0]
	if service.CPU.Usage == nil || service.CPU.Limit == nil || service.Memory.Headroom == nil ||
		service.CPU.Usage.Mean != 2 || service.CPU.Limit.Min != 8 || service.Memory.Headroom.Min != 600 {
		t.Fatalf("totals: %+v", service)
	}
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded.String(), token) {
		t.Fatal("token leaked in usage")
	}
	if _, err := (Client{URLs: []string{httpServer.URL}, Token: token}).Query(t.Context(), "sjc", from, to); err == nil {
		t.Fatal("accepted mismatched region")
	}

	lifecycleUsage := func(t *testing.T, store *Store, from, to time.Time, expected []hostload.UsageInterval) Usage {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		api, err := observability.NewTokenServer(observability.Config{ListenAddress: "127.0.0.1:9463"}, token, observability.ServerDeps{Registry: observability.NewRegistry(false), Health: new(observability.Health)})
		if err != nil {
			t.Fatal(err)
		}
		api.HandleAuthenticated("GET /v1/usage", store.Handler(func(context.Context, time.Time, time.Time) ([]hostload.UsageInterval, error) {
			return expected, nil
		}))
		listener := httptest.NewServer(api)
		t.Cleanup(listener.Close)
		usage, err := (Client{URLs: []string{listener.URL}, Token: token}).Query(ctx, "gru", from, to)
		if err != nil {
			t.Fatalf("authenticated lifecycle query: %v", err)
		}
		return usage
	}
	// The original fixture values are controlled inputs; API and client are real.
	{
		missing := lifecycleUsage(t, s, from, to, fullWindowInventory(from, to, "production", "a", "b", "a/terrabase", "b/terrabase", "missing", "a/ts-auth"))
		if missing.Complete || len(missing.Missing) != 2 {
			t.Fatalf("missing data claimed complete: %+v", missing)
		}
		var out bytes.Buffer
		if err := WriteTable(&out, missing); err != nil || !strings.Contains(out.String(), "production/terrabase") {
			t.Fatalf("table: %s %v", out.String(), err)
		}
		if _, err := (Client{URLs: []string{httpServer.URL}, Token: token}).Query(t.Context(), "gru", from.Add(-2*time.Hour), to); err == nil {
			t.Fatal("accepted expired window")
		}
		// Also require the authenticated API to reject that exact expired window.
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
			httpServer.URL+"/v1/usage?region=gru&from="+from.Add(-2*time.Hour).Format(time.RFC3339Nano)+"&to="+to.Format(time.RFC3339Nano), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		_, readErr := body.ReadFrom(response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusBadRequest || strings.TrimSpace(body.String()) != "from/to must be an increasing RFC3339 window within the last hour" {
			t.Fatalf("expired API window: status %d, body %q, error %v", response.StatusCode, body.String(), readErr)
		}
	}
	{
		store, from, to := fixtureWithLimit(t, 32)
		store.History.Append(from, []observability.Sample{{Metric: "capacity_cpu_usage", Labels: observability.L("node", "dropped"), Value: 1}})
		lost := lifecycleUsage(t, store, from, to, nil)
		if !lost.Truncated || lost.Complete {
			t.Fatalf("lost coverage was hidden: %+v", lost)
		}
		healthyFrom := from.Truncate(time.Minute).Add(time.Minute)
		recovered := lifecycleUsage(t, store, healthyFrom, to, nil)
		if recovered.Truncated || !recovered.Complete || store.History.Stats().Dropped == 0 {
			t.Fatalf("earlier overflow poisoned healthy coverage: %+v", recovered)
		}
		// A later drop must not conceal the earlier queried loss.
		store.History.Append(to, []observability.Sample{{Metric: "capacity_cpu_usage", Labels: observability.L("node", "another"), Value: 1}})
		lost = lifecycleUsage(t, store, from, healthyFrom, nil)
		if !lost.Truncated {
			t.Fatalf("only the latest drop was retained: %+v", lost)
		}
	}
}

func TestRecordRejectsSpoofedRegionAndThrottles(t *testing.T) {
	s := NewStore("gru")
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion}
	if err := s.Record(hostload.Origin{Cell: "sjc", Node: "a"}, report, nil); err == nil {
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

func fullWindowInventory(from, to time.Time, environment string, identities ...string) []hostload.UsageInterval {
	intervals := make([]hostload.UsageInterval, 0, len(identities))
	for _, identity := range identities {
		node, role, _ := strings.Cut(identity, "/")
		intervals = append(intervals, hostload.UsageInterval{Node: node, Role: role, Environment: environment, From: from, To: to})
	}
	return intervals
}
