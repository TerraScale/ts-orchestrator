package tenant

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// startCell starts one single-server cell and returns a connect function, so
// a test can open the store as several controllers.
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

func TestStoreRefusesInvalidWrites(t *testing.T) {
	store := openStore(t, startCell(t)())
	ctx := t.Context()
	acme := newTenant(t)
	suspended, err := acme.Suspend(t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, suspended); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Create(generation 2) = %v, want ErrInvalid", err)
	}
	created, err := store.Create(ctx, acme)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := acme.Delete(DefaultRetention, t0)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Update(ctx, created.Revision, deleted)
	if err != nil {
		t.Fatal(err)
	}
	// A hand-built resurrection of the deleted tenant never reaches the bucket.
	forged := deleted
	forged.State, forged.RetainUntil, forged.Generation = StateActive, time.Time{}, deleted.Generation+1
	if _, err := store.Update(ctx, stored.Revision, forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Update(resurrection) = %v, want ErrInvalid", err)
	}
	// Nor does one built on a forged copy of the stored record: the store
	// checks the successor against what it holds, not what it is handed.
	forgedPrev := deleted
	forgedPrev.State, forgedPrev.RetainUntil = StateActive, time.Time{}
	resurrected, err := forgedPrev.Suspend(t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, stored.Revision, resurrected); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Update(on a forged prev) = %v, want ErrInvalid", err)
	}
	if _, err := store.Create(ctx, acme); !errors.Is(err, ErrExists) {
		t.Fatalf("Create over a retained tenant = %v, want ErrExists", err)
	}
	if got, err := store.Get(ctx, "0000000000WT9WWA18KD4ET6PG"); err != nil || got.Tenant.State != StateDeleted {
		t.Fatalf("Get = %+v, %v; want the deleted tenant untouched", got, err)
	}

	successorStore := openStore(t, startCell(t)())
	prev := newTenant(t)
	prevStored, err := successorStore.Create(ctx, prev)
	if err != nil {
		t.Fatal(err)
	}
	prevRead, err := successorStore.Get(ctx, prev.ID)
	if err != nil || !reflect.DeepEqual(prevRead, prevStored) || !reflect.DeepEqual(prevRead.Tenant, prev) {
		t.Fatalf("successor initial Get = %+v, %v; want %+v", prevRead, err, prevStored)
	}
	prev = prevRead.Tenant
	good, err := prev.Suspend(t0)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Tenant){
		"skipped generation":    func(n *Tenant) { n.Generation += 1 },
		"replayed":              func(n *Tenant) { n.Generation = prev.Generation },
		"earlier":               func(n *Tenant) { n.UpdatedAt = t0.Add(-time.Second) },
		"moved organization":    func(n *Tenant) { n.Organization = "0000000000SENYWME143WT9XQ0" },
		"moved cell":            func(n *Tenant) { n.Cell = "fra" },
		"rewritten creation":    func(n *Tenant) { n.CreatedAt = t0.Add(-time.Hour) },
		"retention not deleted": func(n *Tenant) { n.RetainUntil = t0.Add(DefaultRetention) },
		"unknown state":         func(n *Tenant) { n.State = "paused" },
		"other schema":          func(n *Tenant) { n.Schema = "terrascale.tenant.v2" },
		"resized in place":      func(n *Tenant) { n.State, n.Spec.Member.CPU = StateActive, 64 },
		"undeclared plan":       func(n *Tenant) { n.State, n.Spec.Plan = StateActive, "scale" },
	} {
		next := good
		edit(&next)
		if _, err := successorStore.Update(ctx, prevRead.Revision, next); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Update = %v, want ErrInvalid", name, err)
		}
		if got, err := successorStore.Get(ctx, prev.ID); err != nil || !reflect.DeepEqual(got, prevRead) {
			t.Fatalf("%s: Get after rejected successor = %+v, %v; want %+v", name, got, err, prevRead)
		}
	}
	goodStored, err := successorStore.Update(ctx, prevRead.Revision, good)
	if err != nil {
		t.Fatalf("Update(lifecycle successor) = %v", err)
	}
	if got, err := successorStore.Get(ctx, prev.ID); err != nil || !reflect.DeepEqual(got, goodStored) ||
		!reflect.DeepEqual(got.Tenant, good) {
		t.Fatalf("Get(lifecycle successor) = %+v, %v; want %+v", got, err, goodStored)
	}

}

// TestStoreConcurrentWritersOneWins stands in for two controllers that read
// one revision on either side of a partition: the second write is refused
// and lands only after it rereads.
func TestStoreConcurrentWritersOneWins(t *testing.T) {
	connect := startCell(t)
	left, right := openStore(t, connect()), openStore(t, connect())
	ctx := t.Context()
	if _, err := left.Create(ctx, newTenant(t)); err != nil {
		t.Fatal(err)
	}
	leftRead, err := left.Get(ctx, "0000000000WT9WWA18KD4ET6PG")
	if err != nil {
		t.Fatal(err)
	}
	rightRead, err := right.Get(ctx, "0000000000WT9WWA18KD4ET6PG")
	if err != nil {
		t.Fatal(err)
	}
	suspend, err := leftRead.Tenant.Suspend(t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := left.Update(ctx, leftRead.Revision, suspend); err != nil {
		t.Fatal(err)
	}
	spec := rightRead.Tenant.Spec
	spec.Members = 1
	scale, err := rightRead.Tenant.Change(spec, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := right.Update(ctx, rightRead.Revision, scale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale Update = %v, want ErrConflict", err)
	}
	reread, err := right.Get(ctx, "0000000000WT9WWA18KD4ET6PG")
	if err != nil || reread.Tenant.State != StateSuspended {
		t.Fatalf("reread = %+v, %v; want the suspension", reread, err)
	}
	// The suspended tenant no longer takes the stale scale; resuming does.
	if _, err := reread.Tenant.Change(spec, t0.Add(2*time.Minute)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("scale of the suspended tenant = %v, want ErrInvalid", err)
	}
	resumed, err := reread.Tenant.Resume(t0.Add(2 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := right.Update(ctx, reread.Revision, resumed); err != nil {
		t.Fatal(err)
	}
}

// TestStoreRefusesTamperedRecords writes past the store, as anyone with KV
// write access could, and expects every read to refuse the record.
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
		"unknown field":           {"0000000000WT9WWA18KD4ET6PG", strings.Replace(valid, `"id":`, `"owner":"mallory","id":`, 1)},
		"invalid members":         {"0000000000WT9WWA18KD4ET6PG", strings.Replace(valid, `"members":3`, `"members":2`, 1)},
		"not json":                {"0000000000WT9WWA18KD4ET6PG", "{"},
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

// TestStoreRefusesDeleteMarkers: tenants are never removed, so a delete
// marker written past the store reads as tampering, never as absence, and
// never frees the ID.
func TestStoreRefusesDeleteMarkers(t *testing.T) {
	js := startCell(t)()
	store := openStore(t, js)
	ctx := t.Context()
	acme := newTenant(t)
	if _, err := store.Create(ctx, acme); err != nil {
		t.Fatal(err)
	}
	kv, err := js.KeyValue(ctx, Bucket)
	if err != nil {
		t.Fatal(err)
	}
	for name, remove := range map[string]func() error{
		"delete": func() error { return kv.Delete(ctx, "0000000000WT9WWA18KD4ET6PG") },
		"purge":  func() error { return kv.Purge(ctx, "0000000000WT9WWA18KD4ET6PG") },
	} {
		if err := remove(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(ctx, "0000000000WT9WWA18KD4ET6PG"); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: Get = %v, want ErrCorrupt", name, err)
		}
		if _, err := store.List(ctx); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: List = %v, want ErrCorrupt", name, err)
		}
		if _, err := store.Create(ctx, acme); !errors.Is(err, ErrExists) {
			t.Errorf("%s: Create = %v, want ErrExists", name, err)
		}
	}
}

func TestStoreListFailsWhenCutShort(t *testing.T) {
	store := openStore(t, startCell(t)())
	if _, err := store.Create(t.Context(), newTenant(t)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if tenants, err := store.List(ctx); err == nil {
		t.Fatalf("List on a cancelled context = %+v, want an error", tenants)
	}
}

// TestStoreRefusesFutureStamps: a caller cannot purge a tenant before its
// retention ends, or create one, by passing a time past the store's clock.
func TestStoreRefusesFutureStamps(t *testing.T) {
	store := openStore(t, startCell(t)())
	store.now = func() time.Time { return t0 }
	ctx := t.Context()
	early, err := New("0000000000WT9WWA18KD4ET6PG", "0000000000GG77KS2XN2FPA9SS", "00000000005C91M54AQR9YGVT5", "gru",
		Spec{Plan: "standard", Members: 3, TerraBase: digestA}, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, early); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Create stamped an hour ahead = %v, want ErrInvalid", err)
	}
	created, err := store.Create(ctx, newTenant(t))
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := created.Tenant.Delete(MinRetention, t0)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Update(ctx, created.Revision, deleted)
	if err != nil {
		t.Fatal(err)
	}
	purged, err := stored.Tenant.Purge(deleted.RetainUntil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, stored.Revision, purged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Purge stamped at retain_until a day early = %v, want ErrInvalid", err)
	}
	store.now = func() time.Time { return deleted.RetainUntil }
	if _, err := store.Update(ctx, stored.Revision, purged); err != nil {
		t.Fatalf("Purge once retention ended = %v", err)
	}
}

// TestStoreCreateRefusesOffPlanResources: the store holds a hand-built
// tenant to its plan, not only tenants made by New.
func TestStoreCreateRefusesOffPlanResources(t *testing.T) {
	store := openStore(t, startCell(t)())
	forged := newTenant(t)
	forged.Spec.Member.MemoryBytes *= 4
	if _, err := store.Create(t.Context(), forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Create with off-plan resources = %v, want ErrInvalid", err)
	}
}
