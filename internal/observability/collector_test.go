package observability

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VictoriaMetrics/metrics"
)

func testCollector(t *testing.T, member string, natsErr error) (*Collector, *atomic.Int32) {
	t.Helper()
	registry := NewRegistry(false)
	set := metrics.NewSet()
	set.NewCounter(Series(MetricPrefix+"member_total", "member", member)).Inc()
	registry.Register(set)
	health := new(Health)
	health.Add(Check{Name: "nats", Run: func(context.Context) (bool, string) { return natsErr == nil, "" }})
	natsCalls := new(atomic.Int32)
	collector, err := NewCollector(CollectorConfig{
		Cell: "gru", Member: member, Role: "controller", Registry: registry, Health: health,
		Authority: func() AuthorityView { return AuthorityView{Leader: true, Ready: true, Epoch: 4, Revision: 9} },
		NATS: func(context.Context) (NATSView, error) {
			natsCalls.Add(1)
			return NATSView{ServerName: "gru-" + member, Routes: 2, ClusterPeers: 3, IsMetaLeader: true,
				Streams:   []StreamView{{Name: "TS_CONTROL_LOG", Messages: 12, Replicas: 3, Leader: "gru-" + member}},
				Consumers: []ConsumerView{{Stream: "TS_DELIVERY_INTENTS", Name: "TS_DELIVERY_WORKER", NumPending: 5}},
			}, natsErr
		},
		Placement: func(context.Context) (PlacementView, error) {
			return PlacementView{StageCounts: map[string]int{"serving": 2, "awaiting-host": 1},
				Databases: []DatabaseView{{DatabaseID: "db", PartitionID: "p0", DesiredSeats: 3, Serving: 2,
					Rollout: &RolloutView{OperationID: "op", Seats: 3, Completed: 1}}}}, nil
		},
		OCI: func() OCIView {
			return OCIView{Operations: []OCIOperationView{{Service: "compute", Operation: "GET /instances/{id}", Calls: 2}}}
		},
		System: func() (SystemView, error) { return SystemView{CPUCount: 2, MemTotalBytes: 100}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return collector, natsCalls
}

func TestCollectorSnapshotAndCachedSections(t *testing.T) {
	t.Parallel()
	collector, natsCalls := testCollector(t, "one", nil)
	snapshot, err := snapshotOverHTTP(t, collector, true)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != SnapshotVersion || snapshot.Cell != "gru" || snapshot.Member != "one" || !snapshot.Ready ||
		snapshot.Authority == nil || snapshot.Authority.Epoch != 4 || snapshot.NATS == nil || snapshot.NATS.Routes != 2 ||
		snapshot.Placement == nil || snapshot.OCI == nil || snapshot.System == nil || snapshot.System.CPUCount != 2 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if !strings.Contains(snapshot.Metrics, `ts_orch_member_total{member="one"} 1`) {
		t.Fatalf("snapshot metrics lack the slice counter:\n%s", snapshot.Metrics)
	}
	for _, want := range []string{"ts_orch_authority_epoch 4", `ts_orch_js_stream_leader_local{stream="TS_CONTROL_LOG"} 1`,
		`ts_orch_js_consumer_num_pending{stream="TS_DELIVERY_INTENTS",consumer="TS_DELIVERY_WORKER"} 5`,
		`ts_orch_terrabase_members{stage="serving"} 2`, `ts_orch_rollout_progress_ratio{database="db",partition="p0"} 0.333`,
		`ts_orch_terrabase_replicas{database="db",partition="p0",state="desired"} 3`, "ts_orch_ready 1"} {
		if !strings.Contains(snapshot.Metrics, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	if _, err := snapshotOverHTTP(t, collector, false); err != nil {
		t.Fatal(err)
	}
	if calls := natsCalls.Load(); calls != 1 {
		t.Fatalf("NATS view loaded %d times within its cache TTL", calls)
	}
}

func TestCollectorReportsFailedSectionByClass(t *testing.T) {
	t.Parallel()
	collector, _ := testCollector(t, "two", errors.New("jsz: secret upstream detail"))
	snapshot, err := snapshotOverHTTP(t, collector, false)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Ready || snapshot.Errors["nats"] != "unavailable" || snapshot.Metrics != "" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestCollectorPreservesOriginalLinkEvidence(t *testing.T) {
	t.Parallel()
	collector, _ := testCollector(t, "one", nil)
	observed := time.Now().UTC().Add(-3 * time.Minute)
	collector.config.Links = func() []RegionLinkProbe {
		return []RegionLinkProbe{{Region: "sfo", ObservedAt: observed, Reach: "ok", WAN: "ok", LagGroups: new(0.0)}}
	}
	for range 2 {
		snapshot, err := snapshotOverHTTP(t, collector, false)
		if err != nil || len(snapshot.Links) != 1 || !snapshot.Links[0].ObservedAt.Equal(observed) || snapshot.Links[0].LagGroups == nil {
			t.Fatalf("snapshot refreshed or lost original link evidence: %+v, %v", snapshot, err)
		}
	}
}

func TestCollectorHTTPRequestsShareLoadAcrossCancellation(t *testing.T) {
	t.Parallel()
	collector, calls := testCollector(t, "cache", nil)
	release, started := make(chan struct{}), make(chan struct{})
	collector.config.NATS = func(ctx context.Context) (NATSView, error) {
		calls.Add(1)
		close(started)
		select {
		case <-release:
			return NATSView{ServerName: "shared"}, nil
		case <-ctx.Done():
			return NATSView{}, ctx.Err()
		}
	}
	endpoint := collectorHTTP(t, collector)
	ctx, cancel := context.WithCancel(t.Context())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL+"/v1/snapshot", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		response, err := endpoint.Client().Do(request)
		if response != nil {
			response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("collection did not start")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request = %v", err)
	}
	waiter, stop := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer stop()
	request, err = http.NewRequestWithContext(waiter, http.MethodGet, endpoint.URL+"/v1/snapshot", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := endpoint.Client().Do(request); !errors.Is(err, context.DeadlineExceeded) {
		if response != nil {
			response.Body.Close()
		}
		t.Fatalf("waiting request = %v", err)
	}
	close(release)
	response, err := endpoint.Client().Get(endpoint.URL + "/v1/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var snapshot MemberSnapshot
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || snapshot.NATS == nil || snapshot.NATS.ServerName != "shared" {
		t.Fatalf("shared collection = %+v, calls %d", snapshot, calls.Load())
	}
}

func TestCollectorHTTPMetricsTruncateCompleteLinesAndEscapeLabels(t *testing.T) {
	t.Parallel()
	collector, _ := testCollector(t, "labels", nil)
	set := metrics.NewSet()
	set.NewCounter(Series(MetricPrefix+"escaped_total", "name", `x"y\z`+"\n")).Inc()
	collector.config.Registry.Register(set)
	snapshot, err := snapshotOverHTTP(t, collector, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snapshot.Metrics, `name="x\"y\\z\n"`) {
		t.Fatalf("escaped metric missing: %s", snapshot.Metrics)
	}
	collector.config.MaxMetricsBytes = len(snapshot.Metrics) - 2
	snapshot, err = snapshotOverHTTP(t, collector, true)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.MetricsTruncated || len(snapshot.Metrics) > collector.config.MaxMetricsBytes || !strings.HasSuffix(snapshot.Metrics, "\n") {
		t.Fatalf("truncation = %+v", snapshot)
	}
}

// A credential list that is only partly readable is still reported, with
// the section marked failed, and every expiry becomes a gauge.
func TestCollectorReportsPartialCredentials(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	collector, err := NewCollector(CollectorConfig{Cell: "gru", Member: "one", Role: "controller",
		Registry: NewRegistry(false), System: func() (SystemView, error) { return SystemView{}, nil },
		Credentials: func() ([]CredentialView, error) {
			return []CredentialView{{Name: "nats server tls", Kind: "tls", NotAfter: expires}}, errors.New("route ca unreadable")
		}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotOverHTTP(t, collector, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Credentials) != 1 || snapshot.Credentials[0].Name != "nats server tls" ||
		snapshot.Errors["credentials"] != "unavailable" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	for _, want := range []string{`ts_orch_credential_expiry_timestamp_seconds{name="nats server tls",kind="tls"} 1791763200`,
		`ts_orch_collect_ok{section="credentials"} 0`} {
		if !strings.Contains(snapshot.Metrics, want) {
			t.Errorf("metrics lack %q:\n%s", want, snapshot.Metrics)
		}
	}
}

func TestCollectorIncludesCurrentKVSnapshotMetadata(t *testing.T) {
	t.Parallel()
	collector, _ := testCollector(t, "snapshots", nil)
	snapshot, err := snapshotOverHTTP(t, collector, false)
	if err != nil || snapshot.KVSnapshots != nil {
		t.Fatalf("absent snapshot provider = %+v, %v", snapshot.KVSnapshots, err)
	}
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	want := KVSnapshotView{State: "failed", IntervalSeconds: 60, CheckTimeoutSeconds: 120, LastCheckAt: now,
		Buckets: []KVSnapshotBucketView{{Bucket: "TS_APPS", State: "failed", LastCheckAt: now,
			LastUploadedAt: now.Add(-time.Hour), LastCurrentAt: now.Add(-time.Minute), Sequence: 7, ErrorClass: "timeout"}}}
	collector.config.KVSnapshots = func() KVSnapshotView { return want }
	for _, state := range []string{"failed", "follower", "paused", "current", "disabled", "unknown"} {
		want.State = state
		want.Overdue = state == "unknown"
		snapshot, err = snapshotOverHTTP(t, collector, false)
		if err != nil || snapshot.KVSnapshots == nil || !reflect.DeepEqual(*snapshot.KVSnapshots, want) {
			t.Fatalf("snapshot metadata = %+v, %v; want %+v", snapshot.KVSnapshots, err, want)
		}
	}

}

func collectorHTTP(t *testing.T, collector *Collector) *httptest.Server {
	t.Helper()
	service, err := NewServer(Config{}, ServerDeps{Registry: collector.config.Registry, Health: new(Health), Snapshots: collector})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(service)
	t.Cleanup(endpoint.Close)
	return endpoint
}

func snapshotOverHTTP(t *testing.T, collector *Collector, metrics bool) (MemberSnapshot, error) {
	t.Helper()
	endpoint := collectorHTTP(t, collector)
	path := "/v1/snapshot"
	if metrics {
		path += "?metrics=1"
	}
	response, err := endpoint.Client().Get(endpoint.URL + path)
	if err != nil {
		return MemberSnapshot{}, err
	}
	defer response.Body.Close()
	var snapshot MemberSnapshot
	err = json.NewDecoder(response.Body).Decode(&snapshot)
	return snapshot, err
}

func metricsOverHTTP(t *testing.T, collector *Collector) string {
	t.Helper()
	endpoint := collectorHTTP(t, collector)
	response, err := endpoint.Client().Get(endpoint.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("metrics = %d %s", response.StatusCode, body)
	}
	return string(body)
}
