package control

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

func deliveryTestKV(t *testing.T) (context.Context, jetstream.KeyValue, jetstream.KeyValue, *nats.Conn) {
	t.Helper()
	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), MaxPayload: messaging.DeliveryOperationMaxMessageBytes})
	if err != nil {
		t.Fatal(err)
	}
	instance.Start()
	t.Cleanup(func() { instance.Shutdown(); instance.WaitForShutdown() })
	if !instance.ReadyForConnections(5 * time.Second) {
		t.Fatal("server unavailable")
	}
	nc, err := nats.Connect(instance.ClientURL(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "delivery", Storage: jetstream.FileStorage, MaxValueSize: messaging.DeliveryOperationMaxValueBytes})
	if err != nil {
		t.Fatal(err)
	}
	leaders, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "leaders", Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, kv, leaders, nc
}

func TestNatsDeliveryStoreDurableCASAndOutage(t *testing.T) {
	ctx, kv, _, nc := deliveryTestKV(t)
	store, err := newNatsDeliveryStore(ctx, kv, nc)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create("operation.test", []byte("accepted"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("operation.test", []byte("conflict")); !errors.Is(err, delivery.ErrStoreConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	updated, err := store.Update(created.Key, created.Revision, []byte("receipt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(created.Key, created.Revision, []byte("stale")); !errors.Is(err, delivery.ErrStoreConflict) {
		t.Fatalf("stale: %v", err)
	}
	reopened, err := newNatsDeliveryStore(ctx, kv, nc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Get(created.Key)
	if err != nil || string(got.Value) != "receipt" || got.Revision != updated.Revision {
		t.Fatalf("reopen: %+v %v", got, err)
	}
	listed, err := reopened.List("operation.")
	if err != nil || len(listed) != 1 {
		t.Fatalf("list: %v %v", listed, err)
	}
	nc.Close()
	if _, err := reopened.Create("operation.outage", []byte("x")); err == nil {
		t.Fatal("outage accepted write")
	}
	if _, err := reopened.List("operation."); err == nil {
		t.Fatal("outage returned successful partial list")
	}
}

func TestSignedDeliveryAdmissionRereadsAuthorityAndGeneration(t *testing.T) {
	ctx, kv, leaders, nc := deliveryTestKV(t)
	coordinator, err := authority.RegionalAuthorityCoordinatorStartAsync(ctx, leaders, "gru", "instance")
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Dispose()
	epoch := coordinator.Snapshot().Epoch
	d := &signedDeliveryDispatcher{connection: nc, cell: "gru", instance: "instance", authority: coordinator, leaders: leaders, store: kv}
	first := deliveryAdmission{Version: 1, OperationID: "operation", PayloadDigest: "payload", IdempotencyDigest: "identity", Generation: 1}
	if err := d.admit(ctx, first, epoch); err != nil {
		t.Fatal(err)
	}
	bound := context.WithValue(ctx, signedDeliveryContextKey{}, signedDeliveryContext{first, epoch})
	request := &delivery.Request{OperationID: first.OperationID}
	if err := d.checkAuthority(bound, request); err != nil {
		t.Fatal(err)
	}
	conflicting := first
	conflicting.PayloadDigest = "different"
	if err := d.admit(ctx, conflicting, epoch); err == nil {
		t.Fatal("idempotency conflict accepted")
	}
	next := first
	next.Generation = 2
	next.OperationID = "next"
	next.IdempotencyDigest = "next"
	if err := d.admit(ctx, next, epoch); err != nil {
		t.Fatal(err)
	}
	if err := d.checkAuthority(bound, request); err == nil {
		t.Fatal("superseded execution permitted")
	}
	if err := d.admit(ctx, first, epoch); err == nil {
		t.Fatal("stale generation permitted")
	}
	entry, err := leaders.Get(ctx, "authority.regional")
	if err != nil {
		t.Fatal(err)
	}
	var lease authority.RegionalAuthorityLeaseDocument
	if err := json.Unmarshal(entry.Value(), &lease); err != nil {
		t.Fatal(err)
	}
	lease.CandidateId = "gru-controller-replacement"
	lease.Epoch++
	body, _ := json.Marshal(lease)
	if _, err := leaders.Update(ctx, "authority.regional", body, entry.Revision()); err != nil {
		t.Fatal(err)
	}
	if err := d.checkLeader(ctx, epoch); err == nil {
		t.Fatal("replaced authority accepted")
	}
	newer := next
	newer.Generation = 3
	newer.IdempotencyDigest = "third"
	if err := d.admit(ctx, newer, epoch); err == nil {
		t.Fatal("fenced admission accepted")
	}
	if _, err := kv.Get(ctx, "signed-delivery.idempotency.third"); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("fenced write: %v", err)
	}
}

func TestNatsDeliveryStoreSurvivesServerRestart(t *testing.T) {
	directory := t.TempDir()
	open := func() (*server.Server, *nats.Conn, jetstream.JetStream) {
		t.Helper()
		instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: directory, MaxPayload: messaging.DeliveryOperationMaxMessageBytes})
		if err != nil {
			t.Fatal(err)
		}
		instance.Start()
		if !instance.ReadyForConnections(5 * time.Second) {
			t.Fatal("server unavailable")
		}
		nc, err := nats.Connect(instance.ClientURL(), nats.NoReconnect())
		if err != nil {
			t.Fatal(err)
		}
		js, err := jetstream.New(nc)
		if err != nil {
			t.Fatal(err)
		}
		return instance, nc, js
	}
	ctx := context.Background()
	first, nc, js := open()
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "delivery", Storage: jetstream.FileStorage, MaxValueSize: messaging.DeliveryOperationMaxValueBytes})
	if err != nil {
		t.Fatal(err)
	}
	store, err := newNatsDeliveryStore(ctx, kv, nc)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise a record larger than the default NATS transport payload.
	body := make([]byte, messaging.DeliveryOperationMaxDocumentBytes)
	for i := range body {
		body[i] = 'x'
	}
	created, err := store.Create("operation.restart", body)
	if err != nil {
		t.Fatal(err)
	}
	nc.Close()
	first.Shutdown()
	first.WaitForShutdown()
	second, nc, js := open()
	defer func() { nc.Close(); second.Shutdown(); second.WaitForShutdown() }()
	kv, err = js.KeyValue(ctx, "delivery")
	if err != nil {
		t.Fatal(err)
	}
	store, err = newNatsDeliveryStore(ctx, kv, nc)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(created.Key)
	if err != nil || record.Revision != created.Revision || len(record.Value) != len(body) {
		t.Fatalf("restart lost durable operation: revision=%d length=%d err=%v", record.Revision, len(record.Value), err)
	}
	if _, err := store.Create(created.Key, []byte("duplicate")); !errors.Is(err, delivery.ErrStoreConflict) {
		t.Fatalf("restart lost CAS identity: %v", err)
	}
}
