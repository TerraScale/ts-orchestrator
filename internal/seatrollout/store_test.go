package seatrollout

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

type epochFence struct{ epoch atomic.Uint64 }

func (fence *epochFence) Current() authority.Snapshot {
	return authority.Snapshot{Ready: true, Leader: true, Epoch: fence.epoch.Load(), Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
}

func (fence *epochFence) Guard(_ context.Context, epoch uint64) error {
	if epoch == 0 || epoch != fence.epoch.Load() {
		return authority.ErrFenced
	}
	return nil
}

func testStore(t *testing.T) (*Store, jetstream.KeyValue, *epochFence) {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
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
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	fence := &epochFence{}
	fence.epoch.Store(3)
	store, err := Open(t.Context(), js, 1, fence)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.KeyValue(t.Context(), Bucket)
	if err != nil {
		t.Fatal(err)
	}
	return store, kv, fence
}

func static(generation uint64) host.Desired {
	return host.Desired{Role: terrabase.Role, Generation: generation}
}

func TestSeatRecordsDrainAndPermit(t *testing.T) {
	store, _, fence := testStore(t)
	ctx := t.Context()
	seat, revision, err := store.Get(ctx, "gru-1-db-1")
	if err != nil || revision != 0 || seat.Drain || seat.Permit != 0 {
		t.Fatalf("absent seat: %+v rev %d err %v", seat, revision, err)
	}
	if granted, err := store.Granted(ctx, "gru-1-db-1", static(1)); err != nil || granted {
		t.Fatalf("an unpermitted seat restarted: %v %v", granted, err)
	}
	if granted, err := store.Granted(ctx, "gru-1-ctl-1", host.Desired{Role: "ts-auth", Generation: 9}); err != nil || !granted {
		t.Fatalf("another role was held: %v %v", granted, err)
	}

	drained := Seat{Node: "gru-1-db-1", Drain: true, DrainedAt: time.Now().UTC(), Epoch: 3}
	if revision, err = store.Put(ctx, drained, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(ctx, drained, 0); err == nil {
		t.Fatal("created a seat twice")
	}
	if got, err := store.Drained(ctx); err != nil || !got["gru-1-db-1"] || len(got) != 1 {
		t.Fatalf("drained=%v err=%v", got, err)
	}
	permitted := drained
	permitted.Permit = 4
	if _, err := store.Put(ctx, permitted, revision+1); err == nil {
		t.Fatal("wrote over a revision it did not read")
	}
	if revision, err = store.Put(ctx, permitted, revision); err != nil {
		t.Fatal(err)
	}
	for generation, want := range map[uint64]bool{3: true, 4: true, 5: false} {
		if granted, err := store.Granted(ctx, "gru-1-db-1", static(generation)); err != nil || granted != want {
			t.Fatalf("generation %d: granted %v err %v", generation, granted, err)
		}
	}

	// A deposed leader's write is refused before it lands.
	fence.epoch.Store(4)
	served := Seat{Node: "gru-1-db-1", Permit: 4, Epoch: 3}
	if _, err := store.Put(ctx, served, revision); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fenced write: %v", err)
	}
	if got, _ := store.Drained(ctx); !got["gru-1-db-1"] {
		t.Fatal("a fenced write undrained the seat")
	}
	served.Epoch = 4
	if _, err := store.Put(ctx, served, revision); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Drained(ctx); err != nil || len(got) != 0 {
		t.Fatalf("drained=%v err=%v", got, err)
	}
	for _, bad := range []Seat{
		{Node: "Gru-1-db-1", Epoch: 4},
		{Node: "gru-1-db-1"},
		{Node: "gru-1-db-1", Drain: true, Epoch: 4},
		{Node: "gru-1-db-1", DrainedAt: time.Now(), Epoch: 4},
	} {
		if _, err := store.Put(ctx, bad, 0); !errors.Is(err, ErrInvalid) {
			t.Fatalf("wrote %+v: %v", bad, err)
		}
	}
}

// Records written past Put are refused by every reader, so a tampered or
// corrupt record publishes no backend set and grants no restart.
func TestTamperedSeatRecordsFailClosed(t *testing.T) {
	for name, wire := range map[string]string{
		"not JSON":         `{`,
		"unknown member":   `{"node":"gru-1-db-1","epoch":1,"permit":9,"force":true}`,
		"another seat":     `{"node":"gru-1-db-2","epoch":1,"permit":9}`,
		"no epoch":         `{"node":"gru-1-db-1","permit":9}`,
		"drain without at": `{"node":"gru-1-db-1","epoch":1,"drain":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			store, kv, _ := testStore(t)
			if _, err := kv.Put(t.Context(), "gru-1-db-1", []byte(wire)); err != nil {
				t.Fatal(err)
			}
			if granted, err := store.Granted(t.Context(), "gru-1-db-1", static(1)); !errors.Is(err, ErrInvalid) || granted {
				t.Fatalf("granted %v err %v", granted, err)
			}
			if _, err := store.Drained(t.Context()); !errors.Is(err, ErrInvalid) {
				t.Fatalf("drained err %v", err)
			}
		})
	}
}
