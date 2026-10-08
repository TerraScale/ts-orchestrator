package machines

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workloadspec"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const epoch = 7

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

func testStore(t *testing.T) (*Store, *epochFence, *server.Server) {
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
	fence.epoch.Store(epoch)
	store, err := OpenStore(t.Context(), js, "gru", 1, fence)
	if err != nil {
		t.Fatal(err)
	}
	return store, fence, srv
}

func createApp(t *testing.T, store *Store, name string) App {
	t.Helper()
	draft := testApp(name)
	draft.ID = ""
	app, err := store.PutApp(t.Context(), epoch, draft)
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func createMachine(t *testing.T, store *Store, app App) Machine {
	t.Helper()
	machine, err := store.PutMachine(t.Context(), epoch, testMachine(app))
	if err != nil {
		t.Fatal(err)
	}
	return machine
}

func TestAppListingsIgnoreUnrelatedCorruptRecords(t *testing.T) {
	store, _, _ := testStore(t)
	app := createApp(t, store, "scoped")
	machine := createMachine(t, store, app)
	other := createApp(t, store, "other")
	otherMachine := createMachine(t, store, other)
	for _, kv := range []jetstream.KeyValue{store.machines, store.statuses} {
		if _, err := kv.Put(t.Context(), otherMachine.ID, []byte(`{"broken":true}`)); err != nil {
			t.Fatal(err)
		}
	}
	machines, err := store.Machines(t.Context(), app.Name)
	if err != nil || len(machines) != 1 || machines[0].ID != machine.ID {
		t.Fatalf("scoped machines = %+v, %v", machines, err)
	}
	statuses, err := store.Statuses(t.Context(), app.Name)
	if err != nil || len(statuses) != 0 {
		t.Fatalf("scoped statuses = %+v, %v", statuses, err)
	}
	if _, err := store.Machines(t.Context(), ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("global inventory must reject corrupt records: %v", err)
	}
	// An interrupted create may leave an index entry without a machine.
	id := entityid.New()
	if _, err := store.index.Put(t.Context(), app.Name+"."+id, []byte(id)); err != nil {
		t.Fatal(err)
	}
	machines, err = store.Machines(t.Context(), app.Name)
	if err != nil || len(machines) != 1 {
		t.Fatalf("interrupted-create lookup = %+v, %v", machines, err)
	}
}

func mustPutMachine(t *testing.T, store *Store, machine Machine) Machine {
	t.Helper()
	machine, err := store.PutMachine(t.Context(), epoch, machine)
	if err != nil {
		t.Fatal(err)
	}
	return machine
}

func TestOpenStoreRejectsBadConfiguration(t *testing.T) {
	for name, open := range map[string]func() error{
		"replicas": func() error { _, err := OpenStore(t.Context(), nil, "gru", 2, &epochFence{}); return err },
		"region":   func() error { _, err := OpenStore(t.Context(), nil, "iad", 1, &epochFence{}); return err },
		"fencer":   func() error { _, err := OpenStore(t.Context(), nil, "gru", 1, nil); return err },
	} {
		if err := open(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestStoreAppVersionsFollowConfigChanges(t *testing.T) {
	store, _, _ := testStore(t)
	ctx := t.Context()
	draft := testApp("ts-auth")
	draft.ID, draft.Version = "", 42 // The store owns both.
	app, err := store.PutApp(ctx, epoch, draft)
	if err != nil || app.Version != 1 || !entityid.Valid(app.ID) || app.Revision == 0 {
		t.Fatalf("create = %+v, %v", app, err)
	}
	if _, err := store.PutApp(ctx, epoch, draft); !errors.Is(err, ErrConflict) {
		t.Fatalf("second create: %v", err)
	}

	// Scaling is not a new version.
	app.Regions = map[string]int{"gru": 5, "fra": 1}
	if app, err = store.PutApp(ctx, epoch, app); err != nil || app.Version != 1 {
		t.Fatalf("scale = %+v, %v", app, err)
	}

	// Neither is rollout policy; what the host runs is.
	app.Update = workloadspec.Update{Strategy: workloadspec.Rolling, MaxUnavailable: 2}
	if app, err = store.PutApp(ctx, epoch, app); err != nil || app.Version != 1 || app.Update.MaxUnavailable != 2 {
		t.Fatalf("update policy = %+v, %v", app, err)
	}
	app.Config.Files = []workloadspec.File{{Path: "/etc/ts-auth/extra.json", Content: "{}"}}
	if app, err = store.PutApp(ctx, epoch, app); err != nil || app.Version != 2 {
		t.Fatalf("config file = %+v, %v", app, err)
	}

	// Nil and empty collections are the same config, and an unchanged app
	// writes nothing.
	same := app
	same.Config.Env = map[string]string{"LOG_LEVEL": "info"}
	same.Config.Services = append([]Service{}, app.Config.Services...)
	again, err := store.PutApp(ctx, epoch, same)
	if err != nil || again.Revision != app.Revision || again.Version != 2 {
		t.Fatalf("unchanged put = %+v, %v", again, err)
	}

	app.Config.Digest = strings.Repeat("b", 64)
	if app, err = store.PutApp(ctx, epoch, app); err != nil || app.Version != 3 {
		t.Fatalf("config change = %+v, %v", app, err)
	}
	stored, err := store.App(ctx, "ts-auth")
	if err != nil || stored.Revision != app.Revision || stored.Version != 3 || stored.ID != app.ID ||
		stored.Update.MaxUnavailable != 2 {
		t.Fatalf("read back = %+v, %v", stored, err)
	}

	for name, mutate := range map[string]func(*App){
		"class":  func(a *App) { a.Class, a.Tenant = ClassTenant, "acme" },
		"tenant": func(a *App) { a.Tenant = "acme" },
		"id":     func(a *App) { a.ID = NewMachineID() },
	} {
		changed := app
		mutate(&changed)
		if _, err := store.PutApp(ctx, epoch, changed); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s change: %v", name, err)
		}
	}
	missing := testApp("missing")
	missing.Revision = 3
	if _, err := store.PutApp(ctx, epoch, missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update of a missing app: %v", err)
	}

	createApp(t, store, "terrabase")
	apps, err := store.Apps(ctx)
	if err != nil || len(apps) != 2 || apps[0].Name != "terrabase" || apps[1].Name != "ts-auth" ||
		apps[1].Revision != app.Revision {
		t.Fatalf("apps = %+v, %v", apps, err)
	}
}

// A writer partitioned from the cell comes back with an old read, whether
// from a get or a list: its compare-and-swap loses and the newer write
// survives.
func TestStoreStaleRevisionLosesToNewerWrite(t *testing.T) {
	store, _, _ := testStore(t)
	ctx := t.Context()
	app := createApp(t, store, "ts-auth")
	listed, err := store.Apps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	partitioned := listed[0]

	app.Config.Digest = strings.Repeat("c", 64)
	if _, err := store.PutApp(ctx, epoch, app); err != nil {
		t.Fatal(err)
	}
	partitioned.Regions = map[string]int{"gru": 9}
	if _, err := store.PutApp(ctx, epoch, partitioned); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale app write: %v", err)
	}
	stored, err := store.App(ctx, "ts-auth")
	if err != nil || stored.Regions["gru"] != 3 || stored.Config.Digest != app.Config.Digest {
		t.Fatalf("stored = %+v, %v", stored, err)
	}

	machine := createMachine(t, store, app)
	stale := machine
	machine.Host = "gru-1-ctl-1"
	mustPutMachine(t, store, machine)
	stale.Host = "gru-1-ctl-2"
	if _, err := store.PutMachine(ctx, epoch, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale machine write: %v", err)
	}
	// The write itself refuses a stale revision, even past the store's
	// read check.
	if err := put(ctx, store, store.apps, epoch, &stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale CAS: %v", err)
	}
}

// A deposed leader keeps its old epoch: none of its writes land.
func TestStoreFencesAStaleAuthorityEpoch(t *testing.T) {
	store, fence, _ := testStore(t)
	ctx := t.Context()
	app := createApp(t, store, "ts-auth")
	machine := createMachine(t, store, app)
	status, err := store.PutStatus(ctx, epoch, Status{ID: machine.ID, App: app.Name, State: StatePending})
	if err != nil {
		t.Fatal(err)
	}
	empty := createApp(t, store, "empty")
	fence.epoch.Store(epoch + 1)

	app.Regions = map[string]int{"gru": 1}
	machine.Desired = DesiredStopped
	status.State = StateStarted
	for name, write := range map[string]func(uint64) error{
		"app":            func(e uint64) error { _, err := store.PutApp(ctx, e, app); return err },
		"machine":        func(e uint64) error { _, err := store.PutMachine(ctx, e, machine); return err },
		"new machine":    func(e uint64) error { _, err := store.PutMachine(ctx, e, testMachine(app)); return err },
		"status":         func(e uint64) error { _, err := store.PutStatus(ctx, e, status); return err },
		"app delete":     func(e uint64) error { return store.DeleteApp(ctx, e, empty) },
		"zero epoch app": func(uint64) error { _, err := store.PutApp(ctx, 0, app); return err },
	} {
		if err := write(epoch); !errors.Is(err, authority.ErrFenced) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	stored, err := store.Machine(ctx, "ts-auth", machine.ID)
	if err != nil || stored.Desired != DesiredStarted {
		t.Fatalf("machine changed under a stale epoch: %+v, %v", stored, err)
	}
	if machines, err := store.Machines(ctx, "ts-auth"); err != nil || len(machines) != 1 {
		t.Fatalf("machines = %d, %v", len(machines), err)
	}
	if _, err := store.App(ctx, "empty"); err != nil {
		t.Fatalf("app deleted under a stale epoch: %v", err)
	}

	// The new leader writes with the current epoch.
	if _, err := store.PutMachine(ctx, epoch+1, machine); err != nil {
		t.Fatal(err)
	}
}

func TestStoreMachineInvariants(t *testing.T) {
	store, _, _ := testStore(t)
	ctx := t.Context()
	if _, err := store.PutMachine(ctx, epoch, testMachine(testApp("ts-auth"))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("machine of a missing app: %v", err)
	}
	app := createApp(t, store, "ts-auth")
	elsewhere := testMachine(app)
	elsewhere.Region = "fra"
	if _, err := store.PutMachine(ctx, epoch, elsewhere); !errors.Is(err, ErrInvalid) {
		t.Fatalf("machine in another region: %v", err)
	}
	orphan := testMachine(app)
	orphan.AppID = NewMachineID()
	if _, err := store.PutMachine(ctx, epoch, orphan); !errors.Is(err, ErrInvalid) {
		t.Fatalf("machine of another app incarnation: %v", err)
	}

	machine := createMachine(t, store, app)
	if _, err := store.PutStatus(ctx, epoch, Status{ID: NewMachineID(), App: app.Name, State: StatePending}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("status without a machine: %v", err)
	}
	for name, mutate := range map[string]func(*Machine){
		"region": func(m *Machine) { m.Region = "fra" },
		"app id": func(m *Machine) { m.AppID = NewMachineID() },
	} {
		changed := machine
		mutate(&changed)
		if _, err := store.PutMachine(ctx, epoch, changed); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s change: %v", name, err)
		}
	}
	machine.Host, machine.FailureDomain = "gru-1-ctl-1", "fault-domain-1"
	machine = mustPutMachine(t, store, machine)
	for name, mutate := range map[string]func(*Machine){
		"host":           func(m *Machine) { m.Host = "gru-1-ctl-2" },
		"failure domain": func(m *Machine) { m.FailureDomain = "fault-domain-2" },
		"unplaced":       func(m *Machine) { m.Host, m.FailureDomain = "", "" },
	} {
		changed := machine
		mutate(&changed)
		if _, err := store.PutMachine(ctx, epoch, changed); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s change: %v", name, err)
		}
	}
	if err := store.DeleteApp(ctx, epoch, app); !errors.Is(err, ErrHasMachines) {
		t.Fatalf("delete of an app with machines: %v", err)
	}
	if err := store.DeleteMachine(ctx, epoch, machine); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delete of a live machine: %v", err)
	}

	machine.Desired = DesiredDestroyed
	machine = mustPutMachine(t, store, machine)
	revived := machine
	revived.Desired = DesiredStarted
	if _, err := store.PutMachine(ctx, epoch, revived); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revived machine: %v", err)
	}
	// A placed machine outlives its process: no status, no delete.
	if err := store.DeleteMachine(ctx, epoch, machine); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delete before the host stopped it: %v", err)
	}
	status, err := store.PutStatus(ctx, epoch, Status{ID: machine.ID, App: app.Name, State: StateStopping})
	if err != nil || status.UpdatedAt.IsZero() {
		t.Fatalf("status = %+v, %v", status, err)
	}
	if err := store.DeleteMachine(ctx, epoch, machine); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delete while stopping: %v", err)
	}
	status.State = StateDestroyed
	if status, err = store.PutStatus(ctx, epoch, status); err != nil {
		t.Fatal(err)
	}
	risen := status
	risen.State = StateStarted
	if _, err := store.PutStatus(ctx, epoch, risen); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revived status: %v", err)
	}
	stale := machine
	stale.Revision--
	if err := store.DeleteMachine(ctx, epoch, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if err := store.DeleteMachine(ctx, epoch, machine); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Machine(ctx, app.Name, machine.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted machine: %v", err)
	}
	if _, err := store.Status(ctx, app.Name, machine.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted status: %v", err)
	}

	// An unplaced machine needs no status to be deleted.
	unplaced := createMachine(t, store, app)
	unplaced.Desired = DesiredDestroyed
	if err := store.DeleteMachine(ctx, epoch, mustPutMachine(t, store, unplaced)); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteApp(ctx, epoch, app); err != nil {
		t.Fatal(err)
	}
	if _, err := store.App(ctx, app.Name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted app: %v", err)
	}
	// A recreated app is a new incarnation: a machine of the old one is
	// refused.
	again := createApp(t, store, app.Name)
	if again.ID == app.ID {
		t.Fatal("recreated app kept its ID")
	}
	if _, err := store.PutMachine(ctx, epoch, testMachine(app)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("machine of the deleted app: %v", err)
	}
}

func TestStoreListsMachinesAndStatusesByApp(t *testing.T) {
	store, _, _ := testStore(t)
	ctx := t.Context()
	auth := createApp(t, store, "ts-auth")
	ts := createApp(t, store, "ts")
	for range 3 {
		machine := createMachine(t, store, auth)
		if _, err := store.PutStatus(ctx, epoch, Status{ID: machine.ID, App: auth.Name, State: StatePending}); err != nil {
			t.Fatal(err)
		}
	}
	createMachine(t, store, ts)
	listed, err := store.Machines(ctx, "ts-auth")
	if err != nil || len(listed) != 3 || listed[0].ID > listed[1].ID || listed[0].Revision == 0 {
		t.Fatalf("ts-auth machines = %+v, %v", listed, err)
	}
	all, err := store.Machines(ctx, "")
	if err != nil || len(all) != 4 || all[0].App != "ts" {
		t.Fatalf("all machines = %+v, %v", all, err)
	}
	statuses, err := store.Statuses(ctx, "ts-auth")
	if err != nil || len(statuses) != 3 || statuses[0].Revision == 0 {
		t.Fatalf("statuses = %+v, %v", statuses, err)
	}
	if statuses, err := store.Statuses(ctx, "ts"); err != nil || len(statuses) != 0 {
		t.Fatalf("ts statuses = %+v, %v", statuses, err)
	}
	if _, err := store.Machines(ctx, "ts.*"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wildcard app: %v", err)
	}
}

// Values written around the store, for example restored from a tampered
// snapshot, are refused rather than used.
func TestStoreRefusesTamperedRecords(t *testing.T) {
	store, _, _ := testStore(t)
	ctx := t.Context()
	app := createApp(t, store, "ts-auth")
	machine := createMachine(t, store, app)

	encode := func(value any) []byte {
		data, err := protocol.EncodeJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	other := testApp("terrabase")
	invalid := testApp("evil")
	invalid.Config.Digest = "not-a-digest"
	cases := map[string]struct {
		key   string
		value []byte
	}{
		"app under another name":   {appKey("evil"), encode(other)},
		"unknown field":            {appKey("evil"), []byte(strings.Replace(string(encode(testApp("evil"))), `"name"`, `"owner":"x","name"`, 1))},
		"invalid record":           {appKey("evil"), encode(invalid)},
		"duplicate field":          {appKey("evil"), []byte(`{"name":"evil","name":"evil"}`)},
		"not json":                 {appKey("evil"), []byte("{")},
		"machine under another ID": {entityid.Derive("wrong-machine", machine.ID), encode(machine)},
		"status under another ID":  {entityid.Derive("wrong-status", machine.ID), encode(Status{ID: machine.ID, App: "ts-auth", State: StateStarted, UpdatedAt: time.Now()})},
	}
	for name, tamper := range cases {
		kv := store.apps
		if strings.HasPrefix(name, "status ") {
			kv = store.statuses
		} else if strings.HasPrefix(name, "machine ") {
			kv = store.machines
		}
		if _, err := kv.Put(ctx, tamper.key, tamper.value); err != nil {
			t.Fatal(err)
		}
		if kv == store.machines {
			if _, err := store.index.Put(ctx, "ts-auth."+tamper.key, []byte(tamper.key)); err != nil {
				t.Fatal(err)
			}
		}
		var getErr, listErr error
		switch {
		case kv == store.apps:
			_, getErr = store.App(ctx, "evil")
			_, listErr = store.Apps(ctx)
		case kv == store.machines:
			_, getErr = store.Machine(ctx, "ts-auth", tamper.key)
			_, listErr = store.Machines(ctx, "")
		default:
			_, getErr = store.Status(ctx, "ts-auth", tamper.key)
			_, listErr = store.Statuses(ctx, "")
		}
		if !errors.Is(getErr, ErrInvalid) || !errors.Is(listErr, ErrInvalid) {
			t.Fatalf("%s: read = %v, list = %v", name, getErr, listErr)
		}
		// The bad record fails only the lists that include it.
		if machines, err := store.Machines(ctx, "ts-auth"); (kv == store.machines && !errors.Is(err, ErrInvalid)) || (kv != store.machines && (err != nil || len(machines) != 1)) {
			t.Fatalf("%s: ts-auth machines = %d, %v", name, len(machines), err)
		}
		if err := kv.Purge(ctx, tamper.key); err != nil {
			t.Fatal(err)
		}
		if kv == store.machines {
			if err := store.index.Purge(ctx, "ts-auth."+tamper.key); err != nil {
				t.Fatal(err)
			}
		}
	}

	// A tampered record cannot be the base of an update either.
	revision, err := store.apps.Put(ctx, appKey("ts-auth"), encode(other))
	if err != nil {
		t.Fatal(err)
	}
	app.Revision = revision
	if _, err := store.PutApp(ctx, epoch, app); !errors.Is(err, ErrInvalid) {
		t.Fatalf("update over a tampered record: %v", err)
	}
}

// A store cut off from its cell fails its reads and writes; it never
// reports a write it could not make.
func TestStoreFailsWhileTheCellIsUnreachable(t *testing.T) {
	store, _, srv := testStore(t)
	app := createApp(t, store, "ts-auth")
	srv.Shutdown()
	srv.WaitForShutdown()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	app.Regions = map[string]int{"gru": 9}
	if _, err := store.PutApp(ctx, epoch, app); err == nil {
		t.Fatal("write succeeded without the cell")
	}
	if err := put(ctx, store, store.apps, epoch, &app); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("unreachable write = %v", err)
	}
	if _, err := store.Apps(ctx); err == nil {
		t.Fatal("list succeeded without the cell")
	}
}

// A status can outlive its machine when a host report races the machine's
// deletion. Writes refuse such a status, and the sweep removes it while
// keeping every live machine's status.
func TestStoreSweepsStatusesWithoutTheirMachine(t *testing.T) {
	store, fence, _ := testStore(t)
	ctx := t.Context()
	app := createApp(t, store, "ts-auth")
	gone, kept := createMachine(t, store, app), createMachine(t, store, app)
	goneStatus, err := store.PutStatus(ctx, epoch, Status{ID: gone.ID, App: app.Name, State: StateStopping})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutStatus(ctx, epoch, Status{ID: kept.ID, App: app.Name, State: StateStarted}); err != nil {
		t.Fatal(err)
	}
	// The machine is deleted between a host report's read and its write.
	if err := store.machines.Delete(ctx, gone.key()); err != nil {
		t.Fatal(err)
	}
	goneStatus.State = StateStopped
	if _, err := store.PutStatus(ctx, epoch, goneStatus); !errors.Is(err, ErrNotFound) {
		t.Fatalf("status update without its machine: %v", err)
	}
	stray := Status{ID: NewMachineID(), App: "terrabase", State: StateFailed, UpdatedAt: time.Now()}
	if err := put(ctx, store, store.statuses, epoch, &stray); err != nil {
		t.Fatal(err)
	}

	fence.epoch.Store(epoch + 1)
	if _, err := store.SweepStatuses(ctx, epoch); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("sweep under a stale epoch: %v", err)
	}
	swept, err := store.SweepStatuses(ctx, epoch+1)
	if err != nil || swept != 2 {
		t.Fatalf("sweep = %d, %v", swept, err)
	}
	statuses, err := store.Statuses(ctx, "")
	if err != nil || len(statuses) != 1 || statuses[0].ID != kept.ID {
		t.Fatalf("statuses after the sweep = %+v, %v", statuses, err)
	}
	if swept, err := store.SweepStatuses(ctx, epoch+1); err != nil || swept != 0 {
		t.Fatalf("second sweep = %d, %v", swept, err)
	}
}
