package observability

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

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
