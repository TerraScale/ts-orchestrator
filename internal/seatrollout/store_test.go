package seatrollout

import (
	"context"
	"github.com/nats-io/nats.go"

	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

type epochFence struct{ epoch atomic.Uint64 }

func (fence *epochFence) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: fence.epoch.Load(), Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
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
