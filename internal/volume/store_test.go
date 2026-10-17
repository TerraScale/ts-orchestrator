package volume

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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
}

func TestStoreCreateRefusesForeignOrPrefilledRecords(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	for name, mutate := range map[string]func(*Volume){
		"other region": func(v *Volume) { v.Region = "fra" },
		"claimed":      func(v *Volume) { v.MachineID = m1 },
		"destroying":   func(v *Volume) { v.DestroyRequestedAt = created },
		"created":      func(v *Volume) { v.Status = Status{State: StateCreated, OCID: "ocid1.volume.oc1.x.y"} },
		"invalid":      func(v *Volume) { v.SizeGB = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			v := testVolume(NewID())
			mutate(&v)
			if _, err := store.Create(ctx, v); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Create() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestStoreRefusesTamperedRecords(t *testing.T) {
	store, kv := testStore(t)
	ctx := t.Context()
	put := func(key string, value any) {
		t.Helper()
		wire, err := protocol.EncodeJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := kv.Put(ctx, key, wire); err != nil {
			t.Fatal(err)
		}
	}

	swapped := testVolume(NewID())
	key := NewID()
	put(key, swapped)
	if _, err := store.Get(ctx, key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("record under another key: Get() = %v, want ErrInvalid", err)
	}
	if _, err := store.List(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatalf("List() over a swapped record = %v, want ErrInvalid", err)
	}
	if err := kv.Purge(ctx, key); err != nil {
		t.Fatal(err)
	}

	foreign := testVolume(NewID())
	foreign.Region = "fra"
	put(foreign.ID, foreign)
	if _, err := store.Get(ctx, foreign.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("record of another cell: Get() = %v, want ErrInvalid", err)
	}

	// A valid record with one unknown field is refused, not partly read.
	unknown := testVolume(NewID())
	wire, err := protocol.EncodeJSON(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, unknown.ID, append(wire[:len(wire)-1], []byte(`,"extra":true}`)...)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, unknown.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("record with an unknown field: Get() = %v, want ErrInvalid", err)
	}

	ocid := "ocid1.volume.oc1.sa-saopaulo-1.abcdef"
	for name, mutate := range map[string]func(*Volume){
		"schema":                func(v *Volume) { v.SchemaVersion = 2 },
		"id":                    func(v *Volume) { v.ID = "vol_UPPER" },
		"app":                   func(v *Volume) { v.App = "bad-" },
		"name":                  func(v *Volume) { v.Name = "has-dash" },
		"region":                func(v *Volume) { v.Region = "GRU" },
		"zone":                  func(v *Volume) { v.Zone = "AD 1" },
		"too small":             func(v *Volume) { v.SizeGB = 49 },
		"too large":             func(v *Volume) { v.SizeGB = MaxSizeGB + 1 },
		"vpus step":             func(v *Volume) { v.VPUsPerGB = 15 },
		"vpus max":              func(v *Volume) { v.VPUsPerGB = 130 },
		"retention":             func(v *Volume) { v.SnapshotRetentionDays = 0 },
		"machine":               func(v *Volume) { v.MachineID = "invalid" },
		"no created_at":         func(v *Volume) { v.CreatedAt = time.Time{} },
		"destroying claimed":    func(v *Volume) { v.DestroyRequestedAt = created; v.MachineID = m1 },
		"state":                 func(v *Volume) { v.Status.State = "extending" },
		"created without ocid":  func(v *Volume) { v.Status.State = StateCreated },
		"ocid kind":             func(v *Volume) { v.Status.OCID = "ocid1.instance.oc1.x.y" },
		"attached without ocid": func(v *Volume) { v.Status.AttachedMachineID = m1 },
		"long message":          func(v *Volume) { v.Status.Message = strings.Repeat("x", maxMessageBytes+1) },
		"pending without request": func(v *Volume) {
			v.Status = Status{State: StatePendingDestroy, OCID: ocid}
		},
		"destroyed but attached": func(v *Volume) {
			v.DestroyRequestedAt = created
			v.Status = Status{State: StateDestroyed, OCID: ocid, AttachedMachineID: m1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := testVolume(NewID())
			key := v.ID
			mutate(&v)
			put(key, v)
			if _, err := store.Get(ctx, key); !errors.Is(err, ErrInvalid) {
				t.Fatalf("persisted malformed record: Get() = %v, want ErrInvalid", err)
			}
		})
	}
	valid := testVolume(NewID())
	valid.VPUsPerGB = 0
	put(valid.ID, valid)
	if got, err := store.Get(ctx, valid.ID); err != nil || got.VPUsPerGB != 0 {
		t.Fatalf("persisted lower-cost volume: Get() = %+v, %v", got, err)
	}
	valid.Status = Status{State: StateCreated, Epoch: 1, OCID: "ocid1.volume.oc1.sa-saopaulo-1.managed-a"}
	put(valid.ID, valid)
	if got, err := store.Get(ctx, valid.ID); err != nil || got.VPUsPerGB != 0 || got.Status != valid.Status {
		t.Fatalf("persisted hyphenated OCID: Get() = %+v, %v", got, err)
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

func TestStoreDestroyIsFinal(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	v := mustCreate(t, store, testVolume(NewID()))
	if _, err := store.RequestDestroy(ctx, v.ID, time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("RequestDestroy() without a time = %v, want ErrInvalid", err)
	}
	destroying, err := store.RequestDestroy(ctx, v.ID, created.Add(time.Hour))
	if err != nil || !destroying.Destroying() {
		t.Fatalf("RequestDestroy() = %+v, %v", destroying, err)
	}
	if again, err := store.RequestDestroy(ctx, v.ID, created.Add(2*time.Hour)); err != nil ||
		!again.DestroyRequestedAt.Equal(destroying.DestroyRequestedAt) {
		t.Fatalf("repeat RequestDestroy() = %+v, %v", again, err)
	}
	if _, err := store.Claim(ctx, v.ID, m1); !errors.Is(err, ErrTransition) {
		t.Fatalf("claim of a destroying volume = %v, want ErrTransition", err)
	}
	undo := destroying
	undo.DestroyRequestedAt = time.Time{}
	if _, err := store.Update(ctx, undo); !errors.Is(err, ErrTransition) {
		t.Fatalf("undo destroy = %v, want ErrTransition", err)
	}
}

func TestStoreListFailsInsteadOfTruncating(t *testing.T) {
	store, _ := testStore(t)
	mustCreate(t, store, testVolume(NewID()))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if list, err := store.List(ctx); err == nil {
		t.Fatalf("List() with a cancelled context = %+v, want an error", list)
	}
}

func TestStoreZonePinsMachineToItsVolume(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	create := func(mutate func(*Volume)) Volume {
		v := testVolume(NewID())
		mutate(&v)
		return mustCreate(t, store, v)
	}
	free := create(func(*Volume) {})
	other := create(func(v *Volume) { v.App = "ts-auth" })
	held := create(func(*Volume) {})
	if _, err := store.Claim(ctx, held.ID, m2); err != nil {
		t.Fatal(err)
	}
	destroying := create(func(*Volume) {})
	if _, err := store.RequestDestroy(ctx, destroying.ID, created); err != nil {
		t.Fatal(err)
	}
	mine := create(func(v *Volume) { v.Zone = "Uocm:SA-SAOPAULO-1-AD-2" })
	if _, err := store.Claim(ctx, mine.ID, m1); err != nil {
		t.Fatal(err)
	}

	for volume, want := range map[string]string{free.ID: testZone, mine.ID: mine.Zone} {
		if zone, err := store.Zone(ctx, "terrabase", m1, []Mount{{Volume: volume, Path: "/data"}}); err != nil || zone != want {
			t.Fatalf("Zone(%s) = %q, %v; want %q", volume, zone, err, want)
		}
	}
	if zone, err := store.Zone(ctx, "terrabase", m1, nil); zone != "" || err != nil {
		t.Fatalf("no mounts: Zone() = %q, %v", zone, err)
	}

	for name, tc := range map[string]struct {
		mounts []Mount
		want   error
	}{
		"unknown volume": {[]Mount{{Volume: NewID(), Path: "/data"}}, ErrNotFound},
		"other app":      {[]Mount{{Volume: other.ID, Path: "/data"}}, ErrNotFound},
		"held elsewhere": {[]Mount{{Volume: held.ID, Path: "/data"}}, ErrTransition},
		"destroying":     {[]Mount{{Volume: destroying.ID, Path: "/data"}}, ErrTransition},
		"two volumes":    {[]Mount{{Volume: free.ID, Path: "/a"}, {Volume: mine.ID, Path: "/b"}}, ErrInvalid},
		"relative":       {[]Mount{{Volume: free.ID, Path: "data"}}, ErrInvalid},
		"unclean":        {[]Mount{{Volume: free.ID, Path: "/data/../etc"}}, ErrInvalid},
		"root":           {[]Mount{{Volume: free.ID, Path: "/"}}, ErrInvalid},
		"colon":          {[]Mount{{Volume: free.ID, Path: "/data:/etc"}}, ErrInvalid},
		"space":          {[]Mount{{Volume: free.ID, Path: "/my data"}}, ErrInvalid},
		"proc":           {[]Mount{{Volume: free.ID, Path: "/proc/self"}}, ErrInvalid},
		"dev":            {[]Mount{{Volume: free.ID, Path: "/dev"}}, ErrInvalid},
		"bad volume id":  {[]Mount{{Volume: "data", Path: "/data"}}, ErrInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.Zone(ctx, "terrabase", m1, tc.mounts); !errors.Is(err, tc.want) {
				t.Fatalf("Zone() = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := store.Zone(ctx, "terrabase", m1, []Mount{{Volume: free.ID, Path: "/devices"}}); err != nil {
		t.Fatalf("/devices is not under /dev: %v", err)
	}
}

// closingKV ends its key watch after one entry without the end-of-values
// marker, as a watch does when its connection drops.
type closingKV struct {
	jetstream.KeyValue
	entry jetstream.KeyValueEntry
}

type closingWatcher chan jetstream.KeyValueEntry

func (w closingWatcher) Updates() <-chan jetstream.KeyValueEntry { return w }
func (w closingWatcher) Stop() error                             { return nil }

func (kv closingKV) WatchAll(context.Context, ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	updates := make(closingWatcher, 1)
	updates <- kv.entry
	close(updates)
	return updates, nil
}

func TestStoreListFailsWhenTheWatchEndsEarly(t *testing.T) {
	store, kv := testStore(t)
	v := mustCreate(t, store, testVolume(NewID()))
	entry, err := kv.Get(t.Context(), v.ID)
	if err != nil {
		t.Fatal(err)
	}
	partial := &Store{kv: closingKV{KeyValue: kv, entry: entry}, region: store.region}
	if list, err := partial.List(t.Context()); err == nil {
		t.Fatalf("List() over a watch that ended early = %+v, want an error", list)
	}
}
