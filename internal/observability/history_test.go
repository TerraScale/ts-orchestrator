package observability

import (
	"context"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestHistoryDownsamplesIntoTiers(t *testing.T) {
	history := NewHistory(HistoryConfig{Interval: 10 * time.Second})
	base := time.Now().Add(-2 * time.Hour).Truncate(5 * time.Minute)
	// Two hours of samples every 10s with value = minute index.
	for step := range 720 {
		at := base.Add(time.Duration(step) * 10 * time.Second)
		history.Append(at, []Sample{{Metric: "m", Labels: L("member", "a"), Value: float64(step / 6)}})
	}
	raw := history.Range(HistoryQuery{Metric: "m", Start: base, End: base.Add(3 * time.Hour), Tier: TierRaw})
	if len(raw.Series) != 1 || len(raw.Series[0].Points) != 360 {
		t.Fatalf("raw keeps one hour: %d points", len(raw.Series[0].Points))
	}
	minute := history.Range(HistoryQuery{Metric: "m", Start: base, End: base.Add(3 * time.Hour), Tier: Tier1m})
	points := minute.Series[0].Points
	if len(points) != 120 {
		t.Fatalf("1m points = %d", len(points))
	}
	if points[3].Value != 3 || points[3].Min != 3 || points[3].Max != 3 {
		t.Fatalf("1m point = %+v", points[3])
	}
	five := history.Range(HistoryQuery{Metric: "m", Start: base, End: base.Add(3 * time.Hour), Tier: Tier5m})
	fivePoints := five.Series[0].Points
	if len(fivePoints) != 24 || fivePoints[0].Value != 2 || fivePoints[0].Min != 0 || fivePoints[0].Max != 4 {
		t.Fatalf("5m points = %d first %+v", len(fivePoints), fivePoints[0])
	}
	// Automatic tier choice follows the requested start.
	if auto := history.Range(HistoryQuery{Metric: "m", Start: time.Now().Add(-90 * time.Minute)}); auto.Series[0].Tier != Tier1m {
		t.Fatalf("auto tier = %s", auto.Series[0].Tier)
	}
	if TierFor(time.Now().Add(-10*time.Minute), time.Now()) != TierRaw ||
		TierFor(time.Now().Add(-12*time.Hour), time.Now()) != Tier5m {
		t.Fatal("TierFor")
	}
}

func TestHistoryRateHandlesCounterReset(t *testing.T) {
	history := NewHistory(HistoryConfig{Interval: time.Second})
	base := time.Now().Add(-time.Minute)
	values := []float64{0, 10, 20, 5, 15}
	for index, value := range values {
		history.Append(base.Add(time.Duration(index)*time.Second), []Sample{{Metric: "c", Value: value, Counter: true}})
	}
	result := history.Range(HistoryQuery{Metric: "c", Start: base, Rate: true, Tier: TierRaw})
	want := []float64{10, 10, 5, 10}
	points := result.Series[0].Points
	if len(points) != len(want) {
		t.Fatalf("points = %+v", points)
	}
	for index, point := range points {
		if point.Value != want[index] {
			t.Fatalf("rate[%d] = %v want %v", index, point.Value, want[index])
		}
	}
	// A counter's plain value is its last sample.
	plain := history.Range(HistoryQuery{Metric: "c", Start: base, Tier: Tier1m})
	if last := plain.Series[0].Points[len(plain.Series[0].Points)-1]; last.Value != 15 && last.Value != 5 {
		t.Fatalf("counter value = %+v", last)
	}
}

func TestHistoryLabelsBoundsAndStaleSeries(t *testing.T) {
	history := NewHistory(HistoryConfig{MaxSeries: 3})
	now := time.Now()
	history.Append(now.Add(-15*24*time.Hour), []Sample{{Metric: "old", Value: 1}})
	history.Append(now, []Sample{
		{Metric: "m", Labels: L("member", "a", "role", "x"), Value: 1},
		{Metric: "m", Labels: L("role", "y", "member", "b"), Value: 2},
		{Metric: "m", Labels: L("member", "c"), Value: 3},
		{Metric: "nan", Value: math.NaN()},
	})
	if stats := history.Stats(); stats.Series != 3 || stats.Dropped != 0 {
		t.Fatalf("stats = %+v (the expired series must free its slot)", stats)
	}
	history.Append(now, []Sample{{Metric: "m", Labels: L("member", "d"), Value: 4}})
	if stats := history.Stats(); stats.Series != 3 || stats.Dropped != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if got := history.Range(HistoryQuery{Metric: "m", Labels: map[string]string{"role": ""}}); len(got.Series) != 2 {
		t.Fatalf("label presence filter = %d", len(got.Series))
	}
	if got := history.Range(HistoryQuery{Metric: "m", Labels: map[string]string{"member": "b"}}); len(got.Series) != 1 ||
		got.Series[0].Labels["role"] != "y" {
		t.Fatalf("label value filter = %+v", got.Series)
	}
	if got := history.Range(HistoryQuery{Metric: "m", MaxSeries: 1}); !got.Truncated {
		t.Fatal("expected truncation")
	}
	if latest := history.Latest("m", map[string]string{"member": "a"}); latest["member=a,role=x"] != 1 {
		t.Fatalf("latest = %v", latest)
	}
	if metrics := history.Metrics(); len(metrics) != 1 || metrics[0] != "m" {
		t.Fatalf("metrics = %v (the expired series must be pruned)", metrics)
	}
}

func TestHistoryExportImportRoundTrip(t *testing.T) {
	history := NewHistory(HistoryConfig{Interval: 10 * time.Second})
	base := time.Now().Add(-30 * time.Minute)
	for step := range 180 {
		var samples []Sample
		for member := range 20 {
			samples = append(samples, Sample{Metric: "m", Labels: L("member", fmt.Sprint(member)), Value: float64(step)})
		}
		history.Append(base.Add(time.Duration(step)*10*time.Second), samples)
	}
	data, err := history.Export(0)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewHistory(HistoryConfig{})
	if err := restored.Import(data); err != nil {
		t.Fatal(err)
	}
	got := restored.Range(HistoryQuery{Metric: "m", Start: base, Tier: Tier1m, Labels: map[string]string{"member": "3"}})
	if len(got.Series) != 1 || len(got.Series[0].Points) < 29 {
		t.Fatalf("restored = %+v", got.Series)
	}
	small, err := history.Export(600)
	if err != nil || len(small) > 600 {
		t.Fatalf("bounded export len=%d err=%v", len(small), err)
	}
	if err := NewHistory(HistoryConfig{}).Import(small); err != nil {
		t.Fatal(err)
	}
	if err := restored.Import([]byte("not gzip")); err == nil {
		t.Fatal("garbage must be rejected")
	}
}

func TestHistoryConcurrentAppendAndRange(t *testing.T) {
	history := NewHistory(HistoryConfig{Interval: time.Millisecond, MaxSeries: 64})
	var group sync.WaitGroup
	start := time.Now()
	for worker := range 8 {
		group.Go(func() {
			for step := range 300 {
				history.Append(start.Add(time.Duration(step)*time.Millisecond),
					[]Sample{{Metric: "m", Labels: L("w", fmt.Sprint(worker)), Value: float64(step)}})
			}
		})
		group.Go(func() {
			for range 100 {
				_ = history.Range(HistoryQuery{Metric: "m", Start: start, End: start.Add(time.Second)})
				_, _ = history.Export(4096)
			}
		})
	}
	group.Wait()
	if stats := history.Stats(); stats.Series != 8 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestSnapshotSamplerDerivesSeries(t *testing.T) {
	sampler := &SnapshotSampler{}
	member := func(user, idle float64) MemberSnapshot {
		return MemberSnapshot{Member: "c1", Role: "controller", Ready: true,
			Authority: &AuthorityView{Leader: true, Epoch: 7},
			System: &SystemView{CPUSeconds: CPUSeconds{User: user, Idle: idle}, MemTotalBytes: 100, MemAvailBytes: 25,
				Filesystems: []FilesystemView{{Role: "nats", SizeBytes: 200, AvailBytes: 50}}},
			NATS: &NATSView{ServerName: "c1", InMsgs: 10, Streams: []StreamView{{Name: "S", Messages: 3, Leader: "c1"}},
				Consumers: []ConsumerView{{Stream: "S", Name: "C", NumPending: 4}}},
			OCI: &OCIView{Operations: []OCIOperationView{{Service: "compute", Operation: "Launch", Calls: 5, Throttled: 1}}},
			Placement: &PlacementView{Databases: []DatabaseView{{DatabaseID: "orders", PartitionID: "p0", DesiredSeats: 2, Serving: 1,
				Rollout: &RolloutView{OperationID: "op", Seats: 2, Completed: 1}}}, StageCounts: map[string]int{"serving": 1}},
		}
	}
	sampler.Samples(ClusterSnapshot{Expected: []string{"c1", "c2"}, Members: []MemberSnapshot{member(10, 10)}, Missing: []string{"c2"}})
	samples := sampler.Samples(ClusterSnapshot{Expected: []string{"c1", "c2"}, Members: []MemberSnapshot{member(15, 15)},
		Missing: []string{"c2"}})
	values := map[string]float64{}
	for _, sample := range samples {
		values[seriesKey(sample.Metric, sortedLabels(sample.Labels))] = sample.Value
	}
	checks := map[string]float64{
		HistMembersExpected:                                                   2,
		HistMembersAnswering:                                                  1,
		HistMembersReady:                                                      1,
		HistAuthorityEpoch:                                                    7,
		Series(HistCPUUtilization, "member", "c1"):                            0.5,
		Series(HistMemoryRatio, "member", "c1"):                               0.75,
		Series(HistFSRatio, "member", "c1", "role", "nats"):                   0.75,
		Series(HistStreamMessages, "stream", "S"):                             3,
		Series(HistConsumerPending, "consumer", "C", "stream", "S"):           4,
		Series(HistOCIThrottled, "operation", "compute.Launch"):               1,
		Series(HistRolloutProgress, "operation", "op"):                        0.5,
		Series(HistStageMembers, "stage", "serving"):                          1,
		Series(HistPartitionDesired, "database", "orders", "partition", "p0"): 2,
		Series(HistPartitionServing, "database", "orders", "partition", "p0"): 1,
	}
	for key, want := range checks {
		if got, ok := values[key]; !ok || got != want {
			t.Errorf("%s = %v (present %v), want %v", key, got, ok, want)
		}
	}
}

func TestHistorySamplerSnapshotsToKV(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, _ := jetstream.New(conn)
	snapshots, err := OpenHistorySnapshots(t.Context(), js, 1, 512<<10)
	if err != nil {
		t.Fatal(err)
	}
	status, err := snapshots.kv.Status(t.Context())
	if err != nil || status.TTL() != HistoryRetention {
		t.Fatalf("snapshot retention = %v, error %v", status, err)
	}
	if data, err := snapshots.Load(t.Context(), "ctrl-1"); err != nil || data != nil {
		t.Fatalf("empty load = %v, %v", data, err)
	}
	store := NewHistory(HistoryConfig{Interval: 5 * time.Millisecond})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- HistorySampler{Store: store, Interval: 5 * time.Millisecond, Member: "ctrl-1", Snapshots: snapshots,
			SnapshotInterval: 20 * time.Millisecond, SnapshotLimit: 256 << 10,
			Collect: func(context.Context) []Sample { return []Sample{{Metric: "m", Value: 1}} }}.Run(ctx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, _ := snapshots.Load(t.Context(), "ctrl-1")
		if len(data) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no snapshot saved")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	// A restarted sampler restores the saved series before sampling.
	restored := NewHistory(HistoryConfig{})
	ctx2, cancel2 := context.WithCancel(t.Context())
	_ = HistorySampler{Store: restored, Member: "ctrl-1", Snapshots: snapshots,
		Collect: func(context.Context) []Sample { cancel2(); return nil }}.Run(ctx2)
	if got := restored.Metrics(); len(got) != 1 || got[0] != "m" {
		t.Fatalf("restored metrics = %v", got)
	}
}

func TestDroppedCoverageIsBoundedToRawRetention(t *testing.T) {
	history := NewHistory(HistoryConfig{MaxSeries: 1})
	start := time.Now().Truncate(time.Minute).Add(-1000 * time.Minute)
	for minute := range 1000 {
		at := start.Add(time.Duration(minute) * time.Minute)
		history.Append(at, []Sample{{Metric: "resident", Value: 1}, {Metric: "dropped", Value: 1}})
	}
	last := start.Add(999 * time.Minute)
	if len(history.dropMinutes) != 61 || history.Stats().Dropped != 1000 || !history.DroppedBetween(last, last) || history.DroppedBetween(start, start) {
		t.Fatalf("drop coverage is not bounded: minutes=%d stats=%+v", len(history.dropMinutes), history.Stats())
	}
	history.Append(last.Add(61*time.Minute), []Sample{{Metric: "resident", Value: 1}})
	if len(history.dropMinutes) != 0 || history.DroppedBetween(last, last.Add(time.Hour)) {
		t.Fatal("expired drops still poison recovered windows")
	}
}
