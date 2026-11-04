package globalview

import (
	"context"
	json "encoding/json/v2"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func rollupAt(cell string, at time.Time) Rollup {
	return Rollup{
		Version:     Version,
		Cell:        cell,
		ObservedAt:  at,
		Health:      Health{Status: Healthy},
		Controllers: Controllers{Expected: 3, Ready: 3},
	}
}

func startNATS(t *testing.T) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	server, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	t.Cleanup(func() { server.Shutdown(); server.WaitForShutdown() })
	if !server.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	conn, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return conn, js
}

func waitClosed(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("no rollup accepted in 5s")
	}
}

// publishUntil republishes until ch closes, since a subscription made by a
// concurrent Follow may not exist yet when the first publish goes out.
func publishUntil(t *testing.T, ch <-chan struct{}, publish func()) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		publish()
		select {
		case <-ch:
			return
		case <-time.After(50 * time.Millisecond):
		case <-deadline:
			t.Fatal("no rollup accepted in 5s")
		}
	}
}

func TestFollowLoadsAndFollows(t *testing.T) {
	conn, js := startNATS(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	kv, err := OpenBucket(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	last, err := json.Marshal(rollupAt("sjc", now.Add(-time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, "sjc", last); err != nil {
		t.Fatal(err)
	}

	view := NewView("gru", func() []string { return []string{"sjc"} }, nil)
	ch := view.Changed()
	done := make(chan error, 1)
	go view.KeepLastKnown(ctx, kv, func() bool { return false })
	go func() { done <- view.Follow(ctx, conn) }()
	waitClosed(t, ch)
	region, _ := view.Region("sjc")
	if region.Rollup == nil || !region.Rollup.ObservedAt.Equal(now.Add(-time.Second)) {
		t.Fatal("last-known rollup from the bucket not loaded")
	}

	newer := rollupAt("sjc", now)
	newer.Health = Health{Status: Degraded}
	data, err := json.Marshal(newer)
	if err != nil {
		t.Fatal(err)
	}
	publishUntil(t, view.Changed(), func() {
		if err := conn.Publish(protocol.RegionRollupSubject("sjc"), data); err != nil {
			t.Fatal(err)
		}
	})
	region, _ = view.Region("sjc")
	if region.Rollup.Health.Status != Degraded {
		t.Fatalf("held health %q, want the newer %q", region.Rollup.Health.Status, Degraded)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Follow returned %v after cancel", err)
	}
}

func TestKeepLastKnownPersistsWhileLeading(t *testing.T) {
	_, js := startNATS(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	kv, err := OpenBucket(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	view := NewView("gru", func() []string { return []string{"sjc"} }, nil)
	view.Accept(rollupAt("gru", time.Now()))
	go view.KeepLastKnown(ctx, kv, func() bool { return true })
	for {
		if _, err := kv.Get(ctx, "gru"); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("the leader did not persist its rollup")
		case <-time.After(20 * time.Millisecond):
		}
	}
}
