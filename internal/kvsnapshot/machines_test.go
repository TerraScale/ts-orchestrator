package kvsnapshot

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/machines"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

type machineSnapshotFence struct{}

func (machineSnapshotFence) Current() authority.Snapshot         { return authority.Snapshot{Epoch: 1} }
func (machineSnapshotFence) Guard(context.Context, uint64) error { return nil }

func TestMachineAndIndexRestoreTogetherAfterDeleteAndUploadFailure(t *testing.T) {
	js := startJetStream(t)
	store, err := machines.OpenStore(t.Context(), js, "gru", 1, machineSnapshotFence{})
	if err != nil {
		t.Fatal(err)
	}
	config := machines.MachineConfig{Role: "worker", Digest: strings.Repeat("a", 64),
		Resources: placement.Resources{CPU: 1, MemoryBytes: 512 << 20, DiskBytes: 1 << 30}}
	app, err := store.PutApp(t.Context(), 1, machines.App{Name: "snapshot", Class: machines.ClassPlatform, Config: config})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := store.PutMachine(t.Context(), 1, machines.Machine{ID: machines.NewMachineID(), App: app.Name,
		AppID: app.ID, Region: "gru", Version: 1, Config: config, Desired: machines.DesiredDestroyed})
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeObjects()
	snapshotter := snapshotterFor(js, fake, machines.Bucket, machines.MachineBucket)
	if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	document := fake.document(t, machines.MachineBucket)
	if len(document.Entries) != 2 {
		t.Fatalf("machine snapshot has %d entries, want machine plus app lookup", len(document.Entries))
	}
	if err := store.DeleteMachine(t.Context(), 1, machine); err != nil {
		t.Fatal(err)
	}
	fake.putErr = fakeError{503, "Unavailable"}
	if _, err := snapshotter.SnapshotOnce(t.Context()); err == nil {
		t.Fatal("upload failure was ignored")
	}
	for _, want := range []int{1, 0} {
		if want == 0 {
			fake.putErr = nil
			if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		rebuilt := startJetStream(t)
		if _, err := Restore(t.Context(), rebuilt, objectsFor(fake), []string{machines.Bucket, machines.MachineBucket}, 1, time.Now()); err != nil {
			t.Fatal(err)
		}
		restored, err := machines.OpenStore(t.Context(), rebuilt, "gru", 1, machineSnapshotFence{})
		if err != nil {
			t.Fatal(err)
		}
		listed, err := restored.Machines(t.Context(), app.Name)
		if err != nil || len(listed) != want {
			t.Fatalf("restored app has %d machines, want %d: %v", len(listed), want, err)
		}
	}
}
