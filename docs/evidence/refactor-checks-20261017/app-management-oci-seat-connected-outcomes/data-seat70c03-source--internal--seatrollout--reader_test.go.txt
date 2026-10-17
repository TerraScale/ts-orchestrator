package seatrollout

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func seatReaderBroker(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
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

func TestSeatReaderOpensExistingBucketWithoutMutationAuthority(t *testing.T) {
	ctx := t.Context()
	js := seatReaderBroker(t)
	if _, err := OpenReader(ctx, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil JetStream accepted: %v", err)
	}
	if _, err := OpenReader(ctx, js); err == nil {
		t.Fatal("reader opened absent bucket")
	}
	if _, err := js.KeyValue(ctx, Bucket); !errors.Is(err, jetstream.ErrBucketNotFound) {
		t.Fatalf("reader provisioned absent bucket: %v", err)
	}
	fence := new(epochFence)
	fence.epoch.Store(3)
	writer, err := Open(ctx, js, 1, fence)
	if err != nil {
		t.Fatal(err)
	}
	drained := Seat{Node: "gru-1-db-1", Drain: true, DrainedAt: time.Now().UTC(), Permit: 4, Epoch: 3}
	revision, err := writer.Put(ctx, drained, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Put(ctx, Seat{Node: "gru-1-db-2", Epoch: 3}, 0); err != nil {
		t.Fatal(err)
	}
	stream, err := js.Stream(ctx, "KV_"+Bucket)
	if err != nil {
		t.Fatal(err)
	}
	before, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ordered, err := js.Conn().SubscribeSync("$JS.API.STREAM.MSG.GET.KV_" + Bucket)
	if err != nil {
		t.Fatal(err)
	}
	defer ordered.Unsubscribe()
	direct, err := js.Conn().SubscribeSync("$JS.API.DIRECT.GET.>")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Unsubscribe()
	if err := js.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReader(ctx, js)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(reader).(interface {
		Put(context.Context, Seat, uint64) (uint64, error)
	}); ok {
		t.Fatal("reader exposes mutation authority")
	}
	// Reads remain available after the writer's epoch has lost authority.
	fence.epoch.Store(4)
	got, gotRevision, err := reader.Get(ctx, drained.Node)
	if err != nil || gotRevision != revision || !reflect.DeepEqual(got, drained) {
		t.Fatalf("existing drain read: seat=%+v revision=%d err=%v", got, gotRevision, err)
	}
	absent, absentRevision, err := reader.Get(ctx, "gru-1-db-3")
	if err != nil || absentRevision != 0 || absent.Node != "gru-1-db-3" || absent.Drain || absent.Permit != 0 {
		t.Fatalf("absent seat: %+v revision=%d err=%v", absent, absentRevision, err)
	}
	seats, err := reader.Drained(ctx)
	if err != nil || len(seats) != 1 || !seats[drained.Node] {
		t.Fatalf("drained seats=%v err=%v", seats, err)
	}
	after, err := stream.Info(ctx)
	if err != nil || !reflect.DeepEqual(before.Config, after.Config) || before.State.LastSeq != after.State.LastSeq {
		t.Fatalf("reader changed durable bucket: %v", err)
	}
	if err := js.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	count, _, err := ordered.Pending()
	if err != nil {
		t.Fatal(err)
	}
	directCount, _, err := direct.Pending()
	if err != nil || directCount != 0 || count != 4 {
		t.Fatalf("reader bypassed leader: ordered=%d direct=%d err=%v", count, directCount, err)
	}
	if _, err := writer.kv.Put(ctx, drained.Node, []byte(`{"node":"gru-1-db-1","epoch":3,"drain":true,"force":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.Get(ctx, drained.Node); !errors.Is(err, ErrInvalid) {
		t.Fatalf("corrupt drain accepted: %v", err)
	}
	if _, err := reader.Drained(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatalf("corrupt drain published: %v", err)
	}
	if err := writer.kv.Delete(ctx, drained.Node); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.Get(ctx, drained.Node); !errors.Is(err, ErrInvalid) {
		t.Fatalf("deleted drain accepted as absence: %v", err)
	}
}

func TestSeatReaderRejectsIncompatibleBucketWithoutRepairingIt(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*jetstream.KeyValueConfig)
	}{
		{"memory", func(config *jetstream.KeyValueConfig) { config.Storage = jetstream.MemoryStorage }},
		{"history", func(config *jetstream.KeyValueConfig) { config.History = 1 }},
		{"expiry", func(config *jetstream.KeyValueConfig) { config.TTL = time.Minute }},
		{"record-size", func(config *jetstream.KeyValueConfig) { config.MaxValueSize = 8 << 10 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			js := seatReaderBroker(t)
			config := jetstream.KeyValueConfig{Bucket: Bucket, Storage: jetstream.FileStorage, Replicas: 1, History: 4, MaxValueSize: 4 << 10}
			test.change(&config)
			kv, err := js.CreateKeyValue(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			before, err := kv.Status(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenReader(ctx, js); !errors.Is(err, ErrInvalid) {
				t.Fatalf("incompatible bucket accepted: %v", err)
			}
			after, err := kv.Status(ctx)
			if err != nil || !reflect.DeepEqual(before.Config(), after.Config()) || before.Values() != after.Values() {
				t.Fatalf("reader repaired incompatible bucket: %v", err)
			}
		})
	}
}
