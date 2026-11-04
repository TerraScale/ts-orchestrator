package observability

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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
