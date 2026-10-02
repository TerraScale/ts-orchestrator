package capacity

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
)

const gib = uint64(1 << 30)

var observed = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func usage(role storage.VolumeRole, total, used, avail uint64) VolumeUsage {
	return VolumeUsage{Cell: "gru", Node: "host-a", Role: role, MountPath: "/m/" + string(role),
		TotalBytes: total, UsedBytes: used, AvailBytes: avail, InodesTotal: 1 << 20, InodesFree: 1 << 19, ObservedAt: observed}
}

func TestEvaluateThresholds(t *testing.T) {
	cases := []struct {
		name string
		used uint64
		want Level
	}{
		{"half", 50, LevelOK},
		{"warn", 72, LevelWarn},
		{"scale-out", 86, LevelScaleOut},
		{"refuse", 96, LevelCritical},
	}
	for _, test := range cases {
		signal := Evaluate(usage(storage.RoleTerraBaseData, 100*gib, test.used*gib, (100-test.used)*gib), Policy{})
		if signal.Level != test.want {
			t.Fatalf("%s: level %s (%.2f), want %s", test.name, signal.Level, signal.Utilization, test.want)
		}
		if test.want != LevelOK && signal.Reason == "" {
			t.Fatalf("%s: signal has no reason", test.name)
		}
	}
}

func TestEvaluateFloorsAndReservations(t *testing.T) {
	small := usage(storage.RoleBoot, 10*gib, 2*gib, gib/2)
	if got := Evaluate(small, Policy{}); got.Level != LevelCritical || !strings.Contains(got.Reason, "floor") {
		t.Fatalf("free-space floor not enforced: %+v", got)
	}
	inodes := usage(storage.RoleBoot, 100*gib, 10*gib, 90*gib)
	inodes.InodesFree = 10
	if got := Evaluate(inodes, Policy{}); got.Level != LevelCritical {
		t.Fatalf("inode floor not enforced: %+v", got)
	}
	// 40 GiB used, 60 GiB free, but JetStream may still claim 50 GiB of it.
	store := usage(storage.RoleJetStream, 100*gib, 40*gib, 60*gib)
	store.ReservedBytes = 50 * gib
	if got := Evaluate(store, Policy{}); got.Level != LevelScaleOut || got.Utilization < 0.89 {
		t.Fatalf("reservation not counted as used: %+v", got)
	}
	store.ReservedBytes = 70 * gib
	if got := Evaluate(store, Policy{}); got.Level != LevelCritical {
		t.Fatalf("unbacked JetStream reservation is not critical: %+v", got)
	}
}

func TestPolicyValidation(t *testing.T) {
	if err := (Policy{}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Policy{
		{WarnPercent: 90, ScaleOutPercent: 80, RefusePercent: 95},
		{WarnPercent: 70, ScaleOutPercent: 85, RefusePercent: 101},
		{WarnPercent: -1},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("invalid policy accepted: %+v", bad)
		}
	}
}

func TestWorstAndNodeHeadroom(t *testing.T) {
	signals := []Signal{
		Evaluate(usage(storage.RoleTerraBaseData, 100*gib, 50*gib, 50*gib), Policy{}),
		Evaluate(usage(storage.RoleBoot, 100*gib, 80*gib, 20*gib), Policy{}),
		Evaluate(usage(storage.RoleJetStream, 100*gib, 75*gib, 25*gib), Policy{}),
	}
	worst, ok := Worst(signals)
	if !ok || worst.Usage.Role != storage.RoleBoot {
		t.Fatalf("worst = %+v", worst)
	}
	if _, ok := Worst(nil); ok {
		t.Fatal("empty worst reported a signal")
	}
	headroom, ok := NodeHeadroomBytes(signals, "host-a")
	if !ok || headroom != 20*gib {
		t.Fatalf("headroom = %d %v", headroom, ok)
	}
	if _, ok := NodeHeadroomBytes(signals, "host-b"); ok {
		t.Fatal("unknown node has headroom")
	}
}

func TestCollectorMeasuresTargetsAndReportsPartialFailures(t *testing.T) {
	failure := errors.New("no such mount")
	collector := Collector{
		Cell: "gru", Node: "host-a", Now: func() time.Time { return observed },
		Targets: []Target{
			{Role: storage.RoleBoot, Path: "/"},
			{Role: storage.RoleJetStream, Path: "/var/lib/nats", Reserve: func(context.Context) (uint64, error) { return 3 * gib, nil }},
			{Role: storage.RoleTerraBaseData, Path: "/missing", VolumeID: "ocid1.volume.x"},
		},
		Statfs: func(path string) (FSStat, error) {
			if path == "/missing" {
				return FSStat{}, failure
			}
			return FSStat{TotalBytes: 100 * gib, FreeBytes: 40 * gib, AvailBytes: 35 * gib, InodesTotal: 100, InodesFree: 50}, nil
		},
	}
	usages, err := collector.Collect(t.Context())
	if !errors.Is(err, failure) || len(usages) != 2 {
		t.Fatalf("collect = %+v, %v", usages, err)
	}
	if usages[0].UsedBytes != 60*gib || usages[0].AvailBytes != 35*gib || usages[1].ReservedBytes != 3*gib {
		t.Fatalf("unexpected measurements: %+v", usages)
	}
}

func TestRealStatfsOfTempDir(t *testing.T) {
	stat, err := Statfs(t.TempDir())
	if err != nil || stat.TotalBytes == 0 || stat.AvailBytes > stat.TotalBytes {
		t.Fatalf("statfs = %+v, %v", stat, err)
	}
}

func TestUsageStorePublishesWithTTLAndFeedsSignals(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	runtime, err := natscell.Start(ctx, natscell.Config{
		Cell: "lab", Instance: "storage-usage-test", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	if _, err := OpenUsageStore(ctx, runtime.JetStream(), 1, 0, Policy{}); err == nil {
		t.Fatal("usage store without TTL was opened")
	}
	store, err := OpenUsageStore(ctx, runtime.JetStream(), 1, time.Minute, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return observed.Add(10 * time.Second) }
	data := usage(storage.RoleTerraBaseData, 100*gib, 90*gib, 10*gib)
	data.VolumeID = "ocid1.volume.a"
	boot := usage(storage.RoleBoot, 50*gib, 10*gib, 40*gib)
	for _, item := range []VolumeUsage{data, boot, data} {
		if err := store.Publish(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Publish(ctx, VolumeUsage{Cell: "gru"}); err == nil {
		t.Fatal("invalid usage was published")
	}
	signals, err := store.Signals(ctx)
	if err != nil || len(signals) != 2 {
		t.Fatalf("signals = %+v, %v", signals, err)
	}
	worst, _ := Worst(signals)
	if worst.Level != LevelScaleOut || worst.Usage.VolumeID != "ocid1.volume.a" {
		t.Fatalf("worst signal = %+v", worst)
	}
	// Records older than the TTL are ignored even before the server purges them.
	store.now = func() time.Time { return observed.Add(2 * time.Minute) }
	if signals, err := store.Signals(ctx); err != nil || len(signals) != 0 {
		t.Fatalf("expired usage was returned: %+v, %v", signals, err)
	}
	reopened, err := OpenUsageStore(ctx, runtime.JetStream(), 1, time.Hour, Policy{})
	if err != nil || reopened.ttl != time.Minute {
		t.Fatalf("reopen did not keep bucket TTL: %v ttl=%s", err, reopened.ttl)
	}
	reserve := JetStreamReservation(runtime.JetStream(), 1<<30)
	if reserved, err := reserve(ctx); err != nil || reserved == 0 || reserved > 1<<30 {
		t.Fatalf("JetStream reservation = %d, %v", reserved, err)
	}
}

type recordingPublisher struct {
	mu        sync.Mutex
	published []VolumeUsage
}

func (publisher *recordingPublisher) Publish(_ context.Context, usage VolumeUsage) error {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	publisher.published = append(publisher.published, usage)
	return nil
}

func TestRunPublishesAndSignalsUntilCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	publisher := &recordingPublisher{}
	var signals []Signal
	collector := Collector{Cell: "gru", Node: "host-a", Targets: []Target{{Role: storage.RoleBoot, Path: "/"}},
		Statfs: func(string) (FSStat, error) {
			return FSStat{TotalBytes: 100 * gib, FreeBytes: 3 * gib, AvailBytes: 3 * gib, InodesTotal: 10, InodesFree: 5}, nil
		}}
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, collector, publisher, Policy{MinFreeInodes: 1}, time.Hour, func(signal Signal) {
			signals = append(signals, signal)
			cancel()
		})
	}()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run returned %v", err)
	}
	if len(publisher.published) != 1 || len(signals) != 1 || signals[0].Level != LevelCritical {
		t.Fatalf("published=%d signals=%+v", len(publisher.published), signals)
	}
	if err := Run(t.Context(), collector, nil, Policy{}, time.Second, nil); err == nil {
		t.Fatal("run without publisher started")
	}
}
