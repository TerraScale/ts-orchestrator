package tenant

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
)

func startCell(t *testing.T) func() jetstream.JetStream {
	t.Helper()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded NATS did not start")
	}
	t.Cleanup(func() {
		broker.Shutdown()
		broker.WaitForShutdown()
	})
	return func() jetstream.JetStream {
		conn, err := nats.Connect(broker.ClientURL())
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
}

func openStore(t *testing.T, js jetstream.JetStream) *Store {
	t.Helper()
	store, err := OpenStore(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Every test stamp is within a year of t0; the wall clock plays no part.
	store.now = func() time.Time { return t0.Add(365 * 24 * time.Hour) }
	return store
}

func TestStoreRoundTripAndList(t *testing.T) {
	store := openStore(t, startCell(t)())
	ctx := t.Context()
	if tenants, err := store.List(ctx); err != nil || len(tenants) != 0 {
		t.Fatalf("empty List = %v, %v", tenants, err)
	}
	acme := newTenant(t)
	created, err := store.Create(ctx, acme)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, acme); !errors.Is(err, ErrExists) {
		t.Fatalf("second Create = %v, want ErrExists", err)
	}
	beta, err := New("000000000007B370ZNASV1RJBJ", "0000000000SENYWME143WT9XQ0", "0000000000DJCXD2R63PD0AFEM", "gru", Spec{Plan: "starter", Members: 1, TerraBase: digestA}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, beta); err != nil {
		t.Fatal(err)
	}
	suspended, err := acme.Suspend(t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.Update(ctx, created.Revision, suspended)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, "0000000000WT9WWA18KD4ET6PG")
	if err != nil || !reflect.DeepEqual(got, updated) {
		t.Fatalf("Get = %+v, %v; want %+v", got, err, updated)
	}
	tenants, err := store.List(ctx)
	if err != nil || len(tenants) != 2 || tenants[1].Tenant.ID != "0000000000WT9WWA18KD4ET6PG" || tenants[0].Tenant.ID != "000000000007B370ZNASV1RJBJ" ||
		!reflect.DeepEqual(tenants[1], updated) {
		t.Fatalf("List = %+v, %v", tenants, err)
	}
	if _, err := store.Get(ctx, "0000000000YB93Q2ZWXZ0R3WKB"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(missing) = %v, want ErrNotFound", err)
	}

	clockStore := openStore(t, startCell(t)())
	clockCreated, err := clockStore.Create(ctx, newTenant(t))
	if err != nil {
		t.Fatal(err)
	}
	clockRead, err := clockStore.Get(ctx, clockCreated.Tenant.ID)
	if err != nil || !reflect.DeepEqual(clockRead, clockCreated) {
		t.Fatalf("clock-skew initial Get = %+v, %v; want %+v", clockRead, err, clockCreated)
	}
	fast, err := clockRead.Tenant.Suspend(t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	fastStored, err := clockStore.Update(ctx, clockRead.Revision, fast)
	if err != nil {
		t.Fatal(err)
	}
	fastRead, err := clockStore.Get(ctx, fast.ID)
	if err != nil || !reflect.DeepEqual(fastRead, fastStored) {
		t.Fatalf("fast writer Get = %+v, %v; want %+v", fastRead, err, fastStored)
	}
	fast = fastRead.Tenant
	slow, err := fast.Resume(t0)
	if err != nil {
		t.Fatalf("Resume on a slower clock = %v", err)
	}
	slowStored, err := clockStore.Update(ctx, fastRead.Revision, slow)
	if err != nil {
		t.Fatal(err)
	}
	slowRead, err := clockStore.Get(ctx, slow.ID)
	if err != nil || !reflect.DeepEqual(slowRead, slowStored) {
		t.Fatalf("slow writer Get = %+v, %v; want %+v", slowRead, err, slowStored)
	}
	slow = slowRead.Tenant
	if !slow.UpdatedAt.Equal(fast.UpdatedAt) {
		t.Fatalf("UpdatedAt = %v, want the previous %v", slow.UpdatedAt, fast.UpdatedAt)
	}
	deleted, err := slow.Delete(DefaultRetention, t0)
	if err != nil || !deleted.RetainUntil.Equal(fast.UpdatedAt.Add(DefaultRetention)) {
		t.Fatalf("Delete on a slower clock = %+v, %v", deleted, err)
	}
	deletedStored, err := clockStore.Update(ctx, slowRead.Revision, deleted)
	if err != nil {
		t.Fatal(err)
	}
	deletedRead, err := clockStore.Get(ctx, deleted.ID)
	if err != nil || !reflect.DeepEqual(deletedRead, deletedStored) ||
		!deletedRead.Tenant.RetainUntil.Equal(fast.UpdatedAt.Add(DefaultRetention)) {
		t.Fatalf("deleted slow writer Get = %+v, %v; want %+v", deletedRead, err, deletedStored)
	}

}

func TestStoreRefusesTamperedRecords(t *testing.T) {
	connect := startCell(t)
	js := connect()
	store := openStore(t, js)
	ctx := t.Context()
	created, err := store.Create(ctx, newTenant(t))
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.KeyValue(ctx, Bucket)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := kv.Get(ctx, "0000000000WT9WWA18KD4ET6PG")
	if err != nil {
		t.Fatal(err)
	}
	valid := string(entry.Value())
	for name, tc := range map[string]struct{ key, value string }{
		"copied under another id": {"000000000007B370ZNASV1RJBJ", valid},
	} {
		if _, err := kv.Put(ctx, tc.key, []byte(tc.value)); err != nil {
			t.Fatal(err)
		}
		id := strings.TrimPrefix(tc.key, "tenant.")
		if _, err := store.Get(ctx, id); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: Get = %v, want ErrCorrupt", name, err)
		}
		if _, err := store.List(ctx); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: List = %v, want ErrCorrupt", name, err)
		}
		if err := kv.Purge(ctx, tc.key); err != nil {
			t.Fatal(err)
		}
		if _, err := kv.Put(ctx, "0000000000WT9WWA18KD4ET6PG", []byte(valid)); err != nil {
			t.Fatal(err)
		}
	}
	// The stray writes moved the revision, so a writer holding the original
	// read is refused rather than overwriting what it never saw.
	suspended, err := created.Tenant.Suspend(t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, created.Revision, suspended); !errors.Is(err, ErrConflict) {
		t.Fatalf("Update after tampering = %v, want ErrConflict", err)
	}
}
