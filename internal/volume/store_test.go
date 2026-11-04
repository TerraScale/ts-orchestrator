package volume

import (
	"errors"

	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func testStore(t *testing.T) (*Store, jetstream.KeyValue) {
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
	store, err := OpenStore(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	return store, store.kv
}

func mustCreate(t *testing.T, store *Store, v Volume) Volume {
	t.Helper()
	stored, err := store.Create(t.Context(), v)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func TestStoreCreateGetListUpdate(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	a := mustCreate(t, store, testVolume(NewID()))
	b := mustCreate(t, store, testVolume(NewID()))
	if _, err := store.Create(ctx, a); !errors.Is(err, ErrConflict) {
		t.Fatalf("second create = %v, want ErrConflict", err)
	}

	got, err := store.Get(ctx, a.ID)
	if err != nil || got.Revision != a.Revision || !got.CreatedAt.Equal(created) || got.Status.State != StateCreating {
		t.Fatalf("Get() = %+v, %v", got, err)
	}
	if _, err := store.Get(ctx, NewID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing Get() = %v, want ErrNotFound", err)
	}
	list, err := store.List(ctx)
	if err != nil || len(list) != 2 || list[0].ID > list[1].ID || (list[0].ID != a.ID && list[0].ID != b.ID) {
		t.Fatalf("List() = %+v, %v", list, err)
	}

	got.SizeGB = 80
	got.Status = Status{State: StateCreated, Epoch: 2, OCID: "ocid1.volume.oc1.sa-saopaulo-1.abc", SizeGB: 50}
	updated, err := store.Update(ctx, got)
	if err != nil || updated.Revision <= got.Revision {
		t.Fatalf("Update() = %+v, %v", updated, err)
	}
	// A writer holding the old revision, such as a partitioned controller
	// with a stale view, cannot overwrite the newer record.
	got.SizeGB = 90
	if _, err := store.Update(ctx, got); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale Update() = %v, want ErrConflict", err)
	}
	shrink := updated
	shrink.SizeGB = 50
	if _, err := store.Update(ctx, shrink); !errors.Is(err, ErrTransition) {
		t.Fatalf("shrink = %v, want ErrTransition", err)
	}
	// A deposed leader that reads the latest record still cannot write an
	// observation under its older epoch.
	deposed := updated
	deposed.Status.Epoch, deposed.Status.State = 1, StateFailed
	if _, err := store.Update(ctx, deposed); !errors.Is(err, ErrTransition) {
		t.Fatalf("deposed leader Update() = %v, want ErrTransition", err)
	}

	ocid := "ocid1.volume.oc1.sa-saopaulo-1.abcdef"
	prev := testVolume("")
	prev.MachineID = m1
	prev.Status = Status{State: StateCreated, Epoch: 4, OCID: ocid, SizeGB: 100}
	prev.SizeGB = 100
	grown := prev
	grown.SizeGB, grown.VPUsPerGB, grown.SnapshotRetentionDays = 200, 0, 30
	larger := prev
	larger.Status.SizeGB, larger.Status.Epoch = 500, 5
	attached := prev
	attached.Status.AttachedMachineID, attached.Status.Epoch = m1, 5
	released := attached
	released.MachineID = ""
	moving := released
	moving.MachineID = m2
	destroying := released
	destroying.Status.AttachedMachineID = ""
	destroying.DestroyRequestedAt = created
	pending := destroying
	pending.Status.State, pending.Status.Epoch = StatePendingDestroy, 6
	undo := pending
	undo.DestroyRequestedAt = time.Time{}
	undo.Status.State = StateCreated
	gone := pending
	gone.Status.State = StateDestroyed

	type transitionCase struct {
		before []Volume
		next   Volume
		want   error
	}
	cases := map[string]transitionCase{
		"grow and retier":             {before: []Volume{prev}, next: grown},
		"observed size above desired": {before: []Volume{prev}, next: larger},
		"attached":                    {before: []Volume{prev}, next: attached},
		"release":                     {before: []Volume{prev, attached}, next: released},
		"claim while still attached":  {before: []Volume{prev, attached, released}, next: moving},
		"destroy":                     {before: []Volume{prev, attached, released}, next: destroying},
		"pending destroy":             {before: []Volume{prev, attached, released, destroying}, next: pending},
		"destroyed":                   {before: []Volume{prev, attached, released, destroying, pending}, next: gone},
		"undo destroy":                {before: []Volume{prev, attached, released, destroying, pending}, next: undo, want: ErrTransition},
		"change after destroyed":      {before: []Volume{prev, attached, released, destroying, pending, gone}, next: gone, want: ErrTransition},
	}
	for name, mutate := range map[string]func(*Volume){
		"zone":             func(v *Volume) { v.Zone = "Uocm:SA-SAOPAULO-1-AD-2" },
		"app":              func(v *Volume) { v.App = "other" },
		"name":             func(v *Volume) { v.Name = "logs" },
		"created_at":       func(v *Volume) { v.CreatedAt = created.Add(time.Second) },
		"shrink":           func(v *Volume) { v.SizeGB = 50 },
		"status shrink":    func(v *Volume) { v.Status.SizeGB = 50 },
		"steal":            func(v *Volume) { v.MachineID = m2 },
		"rebind ocid":      func(v *Volume) { v.Status.OCID = "ocid1.volume.oc1.sa-saopaulo-1.other" },
		"back to creating": func(v *Volume) { v.Status.State = StateCreating },
		"release and destroy at once": func(v *Volume) {
			v.MachineID = ""
			v.DestroyRequestedAt = created
		},
		// A deposed leader read the record and writes an old observation.
		"older epoch": func(v *Volume) {
			v.Status.Epoch = 3
			v.Status.State = StateFailed
		},
		"status without epoch": func(v *Volume) {
			v.Status.Epoch = 0
			v.Status.Message = "observed"
		},
		"destroyed without pending": func(v *Volume) {
			v.MachineID = ""
			v.DestroyRequestedAt = created
			v.Status.State = StateDestroyed
		},
	} {
		next := prev
		mutate(&next)
		cases[name] = transitionCase{before: []Volume{prev}, next: next, want: ErrTransition}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Each branch starts with a legal native create and keeps its latest revision.
			stored := mustCreate(t, store, testVolume(NewID()))
			steps := append([]Volume{stored}, tc.before...)
			steps = append(steps, tc.next)
			for i, expected := range steps {
				expected.ID, expected.Revision = stored.ID, stored.Revision
				if i > 0 {
					written, err := store.Update(ctx, expected)
					if i == len(steps)-1 && tc.want != nil {
						if !errors.Is(err, tc.want) {
							t.Fatalf("Update() = %v, want %v", err, tc.want)
						}
						expected = stored
					} else {
						if err != nil || written.Revision <= stored.Revision {
							t.Fatalf("Update() = %+v, %v; want a newer revision than %d", written, err, stored.Revision)
						}
						expected.Revision = written.Revision
					}
				}
				got, err := store.Get(ctx, stored.ID)
				if err != nil {
					t.Fatal(err)
				}
				list, err := store.List(ctx)
				if err != nil {
					t.Fatal(err)
				}
				readbacks := []Volume{got}
				for _, listed := range list {
					if listed.ID == stored.ID {
						readbacks = append(readbacks, listed)
					}
				}
				if len(readbacks) != 2 {
					t.Fatalf("List() has %d copies of volume %s, want 1", len(readbacks)-1, stored.ID)
				}
				for _, readback := range readbacks {
					business := readback
					business.CreatedAt, business.DestroyRequestedAt = expected.CreatedAt, expected.DestroyRequestedAt
					if !readback.CreatedAt.Equal(expected.CreatedAt) || !readback.DestroyRequestedAt.Equal(expected.DestroyRequestedAt) || business != expected {
						t.Fatalf("persisted step %d = %+v, want %+v", i, readback, expected)
					}
				}
				stored = got
			}
		})
	}
}

func TestStoreClaimIsExclusive(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	v := mustCreate(t, store, testVolume(NewID()))

	// Two schedulers race to claim the volume for different machines: exactly
	// one wins and the loser sees a conflict or the winner's claim.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, machine := range []string{m1, m2} {
		wg.Go(func() { _, errs[i] = store.Claim(ctx, v.ID, machine) })
	}
	wg.Wait()
	got, err := store.Get(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	winner, loser := 0, 1
	if got.MachineID == m2 {
		winner, loser = 1, 0
	}
	if errs[winner] != nil || !errors.Is(errs[loser], ErrConflict) && !errors.Is(errs[loser], ErrTransition) {
		t.Fatalf("claims = %v, held by %q", errs, got.MachineID)
	}

	holder, other := got.MachineID, m1
	if holder == m1 {
		other = m2
	}
	if again, err := store.Claim(ctx, v.ID, holder); err != nil || again.Revision != got.Revision {
		t.Fatalf("repeat claim = %+v, %v; want unchanged", again, err)
	}
	if _, err := store.Claim(ctx, v.ID, other); !errors.Is(err, ErrTransition) {
		t.Fatalf("steal = %v, want ErrTransition", err)
	}
	if _, err := store.RequestDestroy(ctx, v.ID, created); !errors.Is(err, ErrTransition) {
		t.Fatalf("destroy of a claimed volume = %v, want ErrTransition", err)
	}

	// A stale release from the losing machine changes nothing.
	if stale, err := store.Release(ctx, v.ID, other); err != nil || stale.MachineID != holder {
		t.Fatalf("stale release = %+v, %v", stale, err)
	}
	released, err := store.Release(ctx, v.ID, holder)
	if err != nil || released.MachineID != "" {
		t.Fatalf("release = %+v, %v", released, err)
	}
	if _, err := store.Claim(ctx, v.ID, other); err != nil {
		t.Fatalf("claim after release: %v", err)
	}
}
