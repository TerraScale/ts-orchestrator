package machines

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"

	"github.com/TerraScale/ts-orchestrator/internal/workloadspec"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const epoch = 7

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
