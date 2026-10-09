package observability

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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
	snapshot, err := collector.Snapshot(t.Context(), true)
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
	if _, err := collector.Snapshot(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if calls := natsCalls.Load(); calls != 1 {
		t.Fatalf("NATS view loaded %d times within its cache TTL", calls)
	}
}

func TestCollectorReportsFailedSectionByClass(t *testing.T) {
	t.Parallel()
	collector, _ := testCollector(t, "two", errors.New("jsz: secret upstream detail"))
	snapshot, err := collector.Snapshot(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Ready || snapshot.Errors["nats"] != "unavailable" || snapshot.Metrics != "" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestRegistryTextTruncatesAtLineBoundary(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(false)
	set := metrics.NewSet()
	for _, name := range []string{"a", "b", "c"} {
		set.NewCounter(Series(MetricPrefix+"x_total", "name", name)).Inc()
	}
	registry.Register(set)
	registry.Register(set)
	full, truncated := registry.Text(0)
	if truncated || strings.Count(full, "\n") != 3 {
		t.Fatalf("full text = %q", full)
	}
	text, truncated := registry.Text(len(full) - 2)
	if !truncated || strings.Count(text, "\n") != 2 || !strings.HasSuffix(text, "\n") {
		t.Fatalf("truncated text = %q", text)
	}
}

// A caller's cancellation neither cuts the shared load short nor is pinned
// on later callers.
func TestCacheDoesNotPinCallerCancellation(t *testing.T) {
	t.Parallel()
	cache := Cache[int]{TTL: time.Minute}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := cache.Get(ctx, func(ctx context.Context) (int, error) { return 7, ctx.Err() }); err == nil {
		t.Fatal("a canceled caller returned no error")
	}
	value, err := cache.Get(t.Context(), func(context.Context) (int, error) { return 9, nil })
	if err != nil || value != 7 {
		t.Fatalf("Get after a canceled caller = %d, %v; want the shared load's own result", value, err)
	}
}

// A waiter whose deadline ends returns at once instead of waiting for
// another caller's slow load.
func TestCacheWaiterHonoursItsOwnContext(t *testing.T) {
	t.Parallel()
	cache := Cache[int]{TTL: time.Minute}
	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		_, _ = cache.Get(t.Context(), func(context.Context) (int, error) {
			close(started)
			<-release
			return 1, nil
		})
	}()
	<-started
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	begun := time.Now()
	if _, err := cache.Get(ctx, func(context.Context) (int, error) { return 2, nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter error = %v, want its own deadline", err)
	}
	if waited := time.Since(begun); waited > time.Second {
		t.Fatalf("waiter blocked %s on another caller's load", waited)
	}
	close(release)
}

func TestSeriesEscapesLabelValues(t *testing.T) {
	t.Parallel()
	if got := Series("m", "a", `x"y\z`+"\n"); got != `m{a="x\"y\\z\n"}` {
		t.Fatalf("Series() = %s", got)
	}
	if got := Series("m"); got != "m" {
		t.Fatalf("Series() without labels = %s", got)
	}
	var output bytes.Buffer
	WriteAuthorityMetrics(&output, AuthorityView{})
	if !strings.Contains(output.String(), "ts_orch_authority_leader 0") {
		t.Fatalf("authority metrics = %q", output.String())
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
	snapshot, err := collector.Snapshot(t.Context(), true)
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
	snapshot, err := collector.Snapshot(t.Context(), false)
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
		snapshot, err = collector.Snapshot(t.Context(), false)
		if err != nil || snapshot.KVSnapshots == nil || !reflect.DeepEqual(*snapshot.KVSnapshots, want) {
			t.Fatalf("snapshot metadata = %+v, %v; want %+v", snapshot.KVSnapshots, err, want)
		}
	}
	encoded, err := protocol.EncodeJSON(MemberSnapshot{KVSnapshots: &want})
	if err != nil {
		t.Fatal(err)
	}
	var decoded MemberSnapshot
	if err := protocol.DecodeStrict(encoded, &decoded, 0); err != nil {
		t.Fatal(err)
	}
	if decoded.KVSnapshots == nil || !reflect.DeepEqual(*decoded.KVSnapshots, want) {
		t.Fatalf("snapshot wire metadata = %+v, want %+v", decoded.KVSnapshots, want)
	}
}
