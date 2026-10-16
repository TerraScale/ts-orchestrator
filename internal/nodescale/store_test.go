package nodescale

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func newTestJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream"),
	})
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
	return js
}

func TestStoreLoadsZeroRecordWhenNothingSaved(t *testing.T) {
	store, err := OpenStore(context.Background(), newTestJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	record, revision, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if revision != 0 || !reflect.DeepEqual(record, Record{}) {
		t.Fatalf("empty store loaded %+v at revision %d", record, revision)
	}
}

func TestStoreSaveIsCompareAndSet(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(ctx, newTestJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	first := Record{LastChange: t0, From: 3, Action: &InFlight{ID: entityid.New(), Kind: Up, Step: stepEnroll,
		Started: t0}, Status: Status{Schema: StatusSchema, Cell: "gru", At: t0, Nodes: 3, Want: 4, Action: Up,
		Reason: "cpu 0.90 >= 0.75 for 5m0s"}}
	revision, err := store.Save(ctx, first, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(ctx, first, 0); err != ErrRecordChanged {
		t.Fatalf("second create = %v, want ErrRecordChanged", err)
	}

	second := first
	second.From = 4
	next, err := store.Save(ctx, second, revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(ctx, first, revision); err != ErrRecordChanged {
		t.Fatalf("stale update = %v, want ErrRecordChanged", err)
	}

	loaded, loadedRevision, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loadedRevision != next || !reflect.DeepEqual(loaded, second) {
		t.Fatalf("loaded revision %d record %+v, want revision %d record %+v", loadedRevision, loaded, next, second)
	}
	if err := loaded.Status.Validate(); err != nil {
		t.Fatal(err)
	}
}
