package capacity

import (
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/storage"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const gib = uint64(1 << 30)

var observed = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func usage(role storage.VolumeRole, total, used, avail uint64) VolumeUsage {
	return VolumeUsage{Cell: "gru", Node: "host-a", Role: role, MountPath: "/m/" + string(role),
		TotalBytes: total, UsedBytes: used, AvailBytes: avail, InodesTotal: 1 << 20, InodesFree: 1 << 19, ObservedAt: observed}
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
	token := rand.Text()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: filepath.Join(t.TempDir(), "jetstream"), Authorization: token})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("storage usage broker did not become ready")
	}
	connection, err := nats.Connect(broker.ClientURL(), nats.Token(token))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenUsageStore(ctx, js, 1, 0, Policy{}); err == nil {
		t.Fatal("usage store without TTL was opened")
	}
	store, err := OpenUsageStore(ctx, js, 1, time.Minute, Policy{})
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
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if partial, err := store.Usages(cancelled); err == nil {
		t.Fatalf("a listing cut short by its context looked complete: %+v", partial)
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
	// Reopening with a TTL the configuration validated against its interval
	// reconciles the bucket instead of keeping the old TTL (#127 12053).
	reopened, err := OpenUsageStore(ctx, js, 1, time.Hour, Policy{})
	if err != nil || reopened.ttl != time.Hour {
		t.Fatalf("reopen did not reconcile the bucket TTL: %v %+v", err, reopened)
	}
	status, err := reopened.kv.Status(ctx)
	if err != nil || status.TTL() != time.Hour {
		t.Fatalf("bucket TTL after reopen = %v, %v", status, err)
	}
	reserve := JetStreamReservation(func(ctx context.Context) (uint64, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		usage, err := broker.Jsz(&server.JSzOptions{})
		if err != nil {
			return 0, err
		}
		if usage.Disabled {
			return 0, errors.New("storage usage JetStream is disabled")
		}
		return usage.Store, nil
	}, 1<<30)
	if reserved, err := reserve(ctx); err != nil || reserved == 0 || reserved > 1<<30 {
		t.Fatalf("JetStream reservation = %d, %v", reserved, err)
	}
	// The reservation follows node-local usage, not an account's usage
	// that also counts other nodes' replicas (#127 12052).
	nodeLocal := JetStreamReservation(func(context.Context) (uint64, error) { return 10 << 30, nil }, 40<<30)
	if reserved, err := nodeLocal(ctx); err != nil || reserved != 30<<30 {
		t.Fatalf("node-local reservation = %d, %v", reserved, err)
	}
	if _, err := JetStreamReservation(nil, 1<<30)(ctx); err == nil {
		t.Fatal("a reservation without a usage source was accepted")
	}

	// Broker expiry must remove the entry, independently of the age filter above.
	expiring, err := OpenUsageStore(ctx, js, 1, 2*time.Second, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	fresh := data
	fresh.ObservedAt = time.Now().UTC()
	if err := expiring.Publish(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	key := usageKey(fresh)
	entry, err := expiring.kv.Get(ctx, key)
	if err != nil || entry.Key() != key || entry.Revision() == 0 || len(entry.Value()) == 0 {
		t.Fatalf("fresh broker entry %q = %v, %v", key, entry, err)
	}
	if usages, err := expiring.Usages(ctx); err != nil || len(usages) != 1 || usages[0] != fresh {
		t.Fatalf("fresh broker usages = %+v, %v; want %+v", usages, err, fresh)
	}
	if signals, err := expiring.Signals(ctx); err != nil || len(signals) != 1 || signals[0].Usage != fresh || signals[0].Level != LevelScaleOut {
		t.Fatalf("fresh broker signals = %+v, %v", signals, err)
	}
	expiryCtx, stopExpiry := context.WithTimeout(ctx, 5*time.Second)
	defer stopExpiry()
	poll := time.Tick(25 * time.Millisecond)
	for {
		entry, err := expiring.kv.Get(expiryCtx, key)
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			break
		}
		if err != nil {
			t.Fatalf("broker expiry read %q = %v, %v; context = %v", key, entry, err, expiryCtx.Err())
		}
		select {
		case <-expiryCtx.Done():
			t.Fatalf("broker retained %q after TTL: entry = %v, error = %v, context = %v", key, entry, err, expiryCtx.Err())
		case <-poll:
		}
	}
	if usages, err := expiring.Usages(ctx); err != nil || len(usages) != 0 {
		t.Fatalf("broker-expired usages = %+v, %v", usages, err)
	}
	if signals, err := expiring.Signals(ctx); err != nil || len(signals) != 0 {
		t.Fatalf("broker-expired signals = %+v, %v", signals, err)
	}

	nativeSignals := func(t *testing.T, inputs []VolumeUsage) []Signal {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		// Fresh storage keeps the original node, mount and observation values in every case.
		token := rand.Text()
		broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
			StoreDir: filepath.Join(t.TempDir(), "jetstream"), Authorization: token})
		if err != nil {
			t.Fatal(err)
		}
		broker.Start()
		t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
		if !broker.ReadyForConnections(5 * time.Second) {
			t.Fatal("storage usage broker did not become ready")
		}
		connection, err := nats.Connect(broker.ClientURL(), nats.Token(token))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(connection.Close)
		js, err := jetstream.New(connection)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := OpenUsageStore(ctx, js, 1, time.Minute, Policy{})
		if err != nil {
			t.Fatal(err)
		}
		readerConnection, err := nats.Connect(broker.ClientURL(), nats.Token(token))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(readerConnection.Close)
		readerJS, err := jetstream.New(readerConnection)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := OpenUsageStore(ctx, readerJS, 1, time.Minute, Policy{})
		if err != nil {
			t.Fatal(err)
		}
		reader.now = func() time.Time { return observed.Add(10 * time.Second) }
		for _, input := range inputs {
			if err := publisher.Publish(ctx, input); err != nil {
				t.Fatal(err)
			}
			key := usageKey(input)
			entry, err := reader.kv.Get(ctx, key)
			if err != nil || entry.Key() != key || entry.Revision() == 0 || len(entry.Value()) == 0 {
				t.Fatalf("published entry %q = %v, %v", key, entry, err)
			}
		}
		usages, err := reader.Usages(ctx)
		if err != nil || len(usages) != len(inputs) {
			t.Fatalf("Usages() = %+v, %v; want %d records", usages, err, len(inputs))
		}
		signals, err := reader.Signals(ctx)
		if err != nil || len(signals) != len(inputs) {
			t.Fatalf("Signals() = %+v, %v; want %d records", signals, err, len(inputs))
		}
		signalUsages := make([]VolumeUsage, len(signals))
		for i, signal := range signals {
			signalUsages[i] = signal.Usage
		}
		for _, readbacks := range [][]VolumeUsage{usages, signalUsages} {
			for _, expected := range inputs {
				matches := 0
				for _, readback := range readbacks {
					if usageKey(readback) != usageKey(expected) {
						continue
					}
					matches++
					business := readback
					business.ObservedAt = expected.ObservedAt
					if !readback.ObservedAt.Equal(expected.ObservedAt) || business != expected {
						t.Fatalf("persisted usage = %+v, want %+v", readback, expected)
					}
				}
				if matches != 1 {
					t.Fatalf("readback has %d copies of %s, want 1", matches, usageKey(expected))
				}
			}
		}
		return signals
	}
	for _, test := range []struct {
		name string
		used uint64
		want Level
	}{
		{"half", 50, LevelOK},
		{"warn", 72, LevelWarn},
		{"scale-out", 86, LevelScaleOut},
		{"refuse", 96, LevelCritical},
	} {
		t.Run(test.name, func(t *testing.T) {
			signals := nativeSignals(t, []VolumeUsage{usage(storage.RoleTerraBaseData, 100*gib, test.used*gib, (100-test.used)*gib)})
			signal := signals[0]
			if signal.Level != test.want {
				t.Fatalf("%s: level %s (%.2f), want %s", test.name, signal.Level, signal.Utilization, test.want)
			}
			if test.want != LevelOK && signal.Reason == "" {
				t.Fatalf("%s: signal has no reason", test.name)
			}
		})
	}
	t.Run("free-space floor", func(t *testing.T) {
		small := usage(storage.RoleBoot, 10*gib, 2*gib, gib/2)
		got := nativeSignals(t, []VolumeUsage{small})[0]
		if got.Level != LevelCritical || !strings.Contains(got.Reason, "floor") {
			t.Fatalf("free-space floor not enforced: %+v", got)
		}
	})
	t.Run("inode floor", func(t *testing.T) {
		inodes := usage(storage.RoleBoot, 100*gib, 10*gib, 90*gib)
		inodes.InodesFree = 10
		got := nativeSignals(t, []VolumeUsage{inodes})[0]
		if got.Level != LevelCritical {
			t.Fatalf("inode floor not enforced: %+v", got)
		}
	})
	t.Run("reservation counts as used", func(t *testing.T) {
		reserved := usage(storage.RoleJetStream, 100*gib, 40*gib, 60*gib)
		reserved.ReservedBytes = 50 * gib
		got := nativeSignals(t, []VolumeUsage{reserved})[0]
		if got.Level != LevelScaleOut || got.Utilization < 0.89 {
			t.Fatalf("reservation not counted as used: %+v", got)
		}
	})
	t.Run("unbacked reservation", func(t *testing.T) {
		reserved := usage(storage.RoleJetStream, 100*gib, 40*gib, 60*gib)
		reserved.ReservedBytes = 70 * gib
		got := nativeSignals(t, []VolumeUsage{reserved})[0]
		if got.Level != LevelCritical {
			t.Fatalf("unbacked JetStream reservation is not critical: %+v", got)
		}
	})
	bootUsage := usage(storage.RoleBoot, 100*gib, 60*gib, 40*gib)
	sharedUsage := usage(storage.RoleJetStream, 100*gib, 60*gib, 40*gib)
	sharedUsage.ReservedBytes = 8 * gib
	t.Run("shared filesystem", func(t *testing.T) {
		signals := nativeSignals(t, []VolumeUsage{bootUsage, sharedUsage})
		headroom, ok := NodeHeadroomBytes(signals, "host-a")
		if !ok || headroom != 32*gib {
			t.Fatalf("shared-filesystem headroom = %d %v, want the 8 GiB JetStream reserve subtracted", headroom, ok)
		}
	})
	t.Run("separate filesystem", func(t *testing.T) {
		separate := usage(storage.RoleJetStream, 200*gib, 60*gib, 140*gib)
		separate.ReservedBytes = 8 * gib
		signals := nativeSignals(t, []VolumeUsage{bootUsage, separate})
		headroom, ok := NodeHeadroomBytes(signals, "host-a")
		if !ok || headroom != 40*gib {
			t.Fatalf("separate-filesystem headroom = %d %v, want the full boot headroom", headroom, ok)
		}
	})
	t.Run("exhausted reservation", func(t *testing.T) {
		exhausted := sharedUsage
		exhausted.ReservedBytes = 80 * gib
		signals := nativeSignals(t, []VolumeUsage{bootUsage, exhausted})
		if headroom, _ := NodeHeadroomBytes(signals, "host-a"); headroom != 0 {
			t.Fatalf("over-reserved headroom = %d, want 0", headroom)
		}
	})
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
