package capacity

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	result, err := s.Query(from, to, fullWindowInventory(from, to, "production", "a", "b", "a/terrabase", "b/terrabase"))
	if err != nil || !result.Complete || len(result.Nodes) != 2 || len(result.Replicas) != 2 || len(result.Services) != 1 {
		t.Fatalf("window: %+v %v", result, err)
	}
	service := result.Services[0]
	if service.CPU.Usage.Mean != 2 || service.CPU.Limit.Min != 8 || service.Memory.Headroom.Min != 600 {
		t.Fatalf("totals: %+v", service)
	}
	result, err = s.Query(from, to, fullWindowInventory(from, to, "production", "a", "b", "a/terrabase", "b/terrabase", "missing", "a/ts-auth"))
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
	for _, known := range []bool{true, false} {
		t.Run("allocated requests/"+map[bool]string{true: "known request", false: "unknown request"}[known], func(t *testing.T) {
			store := NewStore("gru")
			report := hostload.Report{SchemaVersion: hostload.SchemaVersion,
				Host:  hostload.HostUsage{CPUCores: 4, MemoryBytes: 8192, CPU: new(0.25), Memory: new(0.5)},
				Roles: []hostload.RoleUsage{{Role: "terrabase"}, {Role: "api"}}}
			requests := map[string]hostload.Request{"terrabase": {CPUCores: 2, MemoryBytes: 1024}}
			if known {
				requests["api"] = hostload.Request{CPUCores: 1, MemoryBytes: 512}
			}
			if err := store.Record(hostload.Origin{Cell: "gru", Node: "a", Environment: "production"}, report, requests); err != nil {
				t.Fatal(err)
			}
			to := time.Now().UTC().Add(time.Second)
			from := to.Add(-10 * time.Second)
			result := lifecycleUsage(t, store, from, to, fullWindowInventory(from, to, "production", "a", "a/terrabase", "a/api"))
			if len(result.Nodes) != 1 || result.Complete || len(result.Missing) != 2 || len(result.Replicas) != 2 || len(result.Services) != 2 {
				t.Fatalf("missing measurements were concealed: %+v", result)
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
			terrabaseFound := false
			for _, service := range result.Services {
				if service.Service == "terrabase" {
					terrabaseFound = true
					if service.CPU.Request == nil || service.CPU.Request.Mean != 2 || service.CPU.Usage != nil {
						t.Fatalf("known service requests were lost with unknown usage: %+v", service)
					}
				}
			}
			if !terrabaseFound {
				t.Fatalf("known service disappeared: %+v", result.Services)
			}
		})
	}
	for _, test := range []struct {
		name                string
		lifetimes           [][3]int
		mean, minimum, peak float64
		bound               float64
	}{
		{"replacement", [][3]int{{0, 0, 30}, {1, 30, 60}}, 1, 1, 1, 2},
		{"staggered start", [][3]int{{0, 0, 60}, {1, 30, 60}}, 1.5, 1, 2, 2},
		{"inactive gap", [][3]int{{0, 0, 20}, {1, 40, 60}}, 2.0 / 3, 0, 1, 2},
		{"reactivation", [][3]int{{0, 0, 20}, {0, 40, 60}}, 2.0 / 3, 0, 1, 1},
	} {
		t.Run("service lifetimes/"+test.name, func(t *testing.T) {
			store := NewStore("gru")
			from := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Minute)
			to := from.Add(time.Minute)
			var expected []hostload.UsageInterval
			for _, lifetime := range test.lifetimes {
				node := []string{"a", "b"}[lifetime[0]]
				start, end := from.Add(time.Duration(lifetime[1])*time.Second), from.Add(time.Duration(lifetime[2])*time.Second)
				expected = append(expected, fullWindowInventory(start, end, "", node, node+"/api")...)
			}
			// Keep delayed reports outside the exact original active lifetimes.
			for _, node := range []string{"a", "b"} {
				for at := from; at.Before(to); at = at.Add(5 * time.Second) {
					value := 100.0
					for _, interval := range expected {
						if interval.Node == node && !at.Before(interval.From) && at.Before(interval.To) {
							value = 1
						}
					}
					appendUsageSample(store, at, node, value)
				}
			}
			usage := lifecycleUsage(t, store, from, to, expected)
			if !usage.Complete || len(usage.Services) != 1 {
				t.Fatalf("active lifetimes were not covered: %+v", usage)
			}
			row := usage.Services[0]
			for _, check := range []struct {
				stat       *Stats
				multiplier float64
			}{
				{row.CPU.Usage, 1}, {row.CPU.Request, 2}, {row.CPU.Limit, 4}, {row.CPU.Headroom, 3},
				{row.Memory.Usage, 100}, {row.Memory.Request, 200}, {row.Memory.Limit, 400}, {row.Memory.Headroom, 300},
			} {
				stat, scale := check.stat, check.multiplier
				if stat == nil || math.Abs(stat.Mean-test.mean*scale) > 1e-9 || stat.Min != test.minimum*scale || stat.Max != test.peak*scale || stat.MaxUpperBound == nil || *stat.MaxUpperBound != test.bound*scale {
					t.Fatalf("misaligned service statistics: %+v, scale %g", stat, scale)
				}
			}
			if test.name == "replacement" {
				var table bytes.Buffer
				if err := WriteTable(&table, usage); err != nil || !strings.Contains(table.String(), "1.00 / 2.00 / 4.00 / 3.00") {
					t.Fatalf("table doubled replacement capacity: %s %v", table.String(), err)
				}
			}
		})
	}
	t.Run("unequal cadence", func(t *testing.T) {
		store := NewStore("gru")
		from := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
		to := from.Add(30 * time.Second)
		for _, node := range []string{"a", "b"} {
			seconds := []int{0, 5, 10, 20, 25}
			if node == "b" {
				seconds = []int{0, 5, 10, 15, 20, 25}
			}
			for _, second := range seconds {
				value := 1.0
				if second >= 10 && second < 20 {
					value = 3
				}
				if node == "b" {
					value = 4 - value
				}
				appendUsageSample(store, from.Add(time.Duration(second)*time.Second), node, value)
			}
		}
		usage := lifecycleUsage(t, store, from, to, fullWindowInventory(from, to, "", "a", "a/api", "b", "b/api"))
		if !usage.Complete || len(usage.Services) != 1 {
			t.Fatalf("cadence fixture incomplete: %+v", usage)
		}
		row := usage.Services[0]
		if row.CPU.Usage == nil || row.CPU.Usage.MaxUpperBound == nil || row.CPU.Headroom == nil || row.CPU.Usage.Mean != 4 || row.CPU.Usage.Min != 4 || row.CPU.Usage.Max != 4 || *row.CPU.Usage.MaxUpperBound != 6 || row.CPU.Headroom.Min != 4 {
			t.Fatalf("replica peaks were treated as simultaneous: %+v", row.CPU)
		}
	})
	for _, missing := range []string{"replica", "interior gap"} {
		t.Run("missing measurements/"+missing, func(t *testing.T) {
			store := NewStore("gru")
			from := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Minute)
			to := from.Add(time.Minute)
			for _, node := range []string{"a", "b"} {
				for second := 0; second < 60; second += 5 {
					if node == "b" && (missing == "replica" || (second >= 20 && second < 45)) {
						continue
					}
					appendUsageSample(store, from.Add(time.Duration(second)*time.Second), node, 1)
				}
			}
			usage := lifecycleUsage(t, store, from, to, fullWindowInventory(from, to, "", "a", "a/api", "b", "b/api"))
			if usage.Complete || len(usage.Services) != 1 || usage.Services[0].CPU.Usage != nil || usage.Services[0].CPU.Headroom != nil {
				t.Fatalf("unknown active telemetry became a numeric total: %+v", usage)
			}
			var table bytes.Buffer
			if err := WriteTable(&table, usage); err != nil || !strings.Contains(table.String(), "? / ? / ? / ?") {
				t.Fatalf("unknown totals disappeared from table: %s %v", table.String(), err)
			}
		})
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
			result, err := s.Query(to.Add(-10*time.Second), to, fullWindowInventory(to.Add(-10*time.Second), to, "production", "a", "a/terrabase", "a/api"))
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
			for _, service := range result.Services {
				if service.Service == "terrabase" && (service.CPU.Request == nil || service.CPU.Request.Mean != 2 || service.CPU.Usage != nil) {
					t.Fatalf("known service requests were lost with unknown usage: %+v", service)
				}
			}
		})
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
