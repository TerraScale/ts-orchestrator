package vmdisk

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDriveLifecycleSnapshotRestoreAndExpansion(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	drive, err := store.Preallocate(ctx, "member-a", 16)
	if err != nil {
		t.Fatal(err)
	}
	if drive.Attachment != AttachmentAttached || drive.Size != 16 {
		t.Fatalf("unexpected drive state: %+v", drive)
	}
	if _, err := store.WriteAt(ctx, "member-a", []byte("before"), 0); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(ctx, "member-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(snapshot.Path, store.Root()+string(os.PathSeparator)) {
		t.Fatalf("snapshot escaped root: %s", snapshot.Path)
	}
	if err := store.Expand(ctx, "member-a", 32); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteAt(ctx, "member-a", []byte("after"), 0); err != nil {
		t.Fatal(err)
	}
	if err := store.Restore(ctx, "member-a", snapshot); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 6)
	if _, err := store.ReadAt(ctx, "member-a", got, 0); err != nil {
		t.Fatal(err)
	}
	if string(got) != "before" {
		t.Fatalf("restored bytes = %q", got)
	}
	state, err := store.Get(ctx, "member-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.Size != 16 || state.Attachment != AttachmentAttached {
		t.Fatalf("unexpected restored state: %+v", state)
	}
	checksum, err := store.Checksum(ctx, "member-a")
	if err != nil || checksum == "" {
		t.Fatalf("checksum = %q, err = %v", checksum, err)
	}

	// Metadata is durable and can be reopened by a restarted controller.
	reopened, err := NewStore(store.Root())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Get(ctx, "member-a"); err != nil || got.Size != 16 {
		t.Fatalf("reopened state = %+v, err = %v", got, err)
	}
}

func TestFaultPlanIsSafeAndUsesInjectedRunner(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	var actions []FaultAction
	store, err := New(Config{
		Root: root,
		Runner: FaultRunnerFunc(func(ctx context.Context, action FaultAction) error {
			if err := contextErr(ctx); err != nil {
				return err
			}
			if !strings.HasPrefix(action.Path, root+string(os.PathSeparator)) {
				t.Fatalf("runner path escaped root: %s", action.Path)
			}
			actions = append(actions, action)
			return fileFaultRunner{}.Apply(ctx, action)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "disk", 16); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyFaultPlan(ctx, "disk", FaultPlan{
		FillBytes: 8,
		Corruptions: []Corruption{{
			Offset: 2, Length: 3, Pattern: 0xee,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0].Kind != FaultCorruption {
		t.Fatalf("actions = %+v", actions)
	}
	if err := store.SetReadOnly(ctx, "disk"); err != nil {
		t.Fatal(err)
	}
	if err := store.Detach(ctx, "disk"); err != nil {
		t.Fatal(err)
	}
	state, err := store.Get(ctx, "disk")
	if err != nil {
		t.Fatal(err)
	}
	if state.Attachment != AttachmentDetached || !state.ReadOnly || state.FilledBytes != 8 {
		t.Fatalf("fault state = %+v", state)
	}
	if _, err := store.ReadAt(ctx, "disk", make([]byte, 1), 0); !errors.Is(err, ErrDetached) {
		t.Fatalf("read while detached = %v", err)
	}
	if err := store.Reattach(ctx, "disk"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteAt(ctx, "disk", []byte{1}, 0); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("write read-only = %v", err)
	}
	if err := store.ClearFaults(ctx, "disk"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteAt(ctx, "disk", []byte{1}, 0); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultFaultRunnerCorruptsAndFillsOnlyFiles(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "disk", 8); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyFaultPlan(ctx, "disk", FaultPlan{FillAll: true, Corruptions: []Corruption{{Offset: 2, Length: 2, Pattern: 0x7f}}}); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 8)
	if _, err := store.ReadAt(ctx, "disk", data, 0); err != nil {
		t.Fatal(err)
	}
	for i, b := range data {
		want := byte(0)
		if i == 2 || i == 3 {
			want = 0x7f
		}
		if b != want {
			t.Fatalf("byte %d = %#x, want %#x", i, b, want)
		}
	}
	state, err := store.Get(ctx, "disk")
	if err != nil {
		t.Fatal(err)
	}
	if !state.FillToENOSPC {
		t.Fatal("fill-all did not produce a guest ENOSPC intent")
	}
	if mode, err := os.Stat(state.Path); err != nil || mode.Mode()&os.ModeDevice != 0 {
		t.Fatalf("drive is not a regular file: mode=%v err=%v", mode, err)
	}
}

func TestRootContainmentAndCancellationRecovery(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"../escape", "/absolute", `nested\\drive`, ".."} {
		if _, err := store.Create(ctx, id, 8); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("id %q error = %v", id, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.Create(canceled, "canceled", 8); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled create = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "drives", "canceled")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled drive remains: %v", err)
	}
	if _, err := store.Create(ctx, "keep", 8); err != nil {
		t.Fatal(err)
	}
	if err := store.Cleanup(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cleanup = %v", err)
	}
	if _, err := store.Get(ctx, "keep"); err != nil {
		t.Fatalf("canceled cleanup damaged drive: %v", err)
	}
	if err := store.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "keep"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cleanup state = %v", err)
	}
}

func TestAttachedArtifactToleratesJailerHardLinkAndRemovalRefusesAliases(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	drive, err := store.Preallocate(ctx, "member-a", 16)
	if err != nil {
		t.Fatal(err)
	}
	// The VMM jailer hard-links a drive artifact into its jail while the
	// guest runs; reads must keep working through that alias.
	jailLink := filepath.Join(t.TempDir(), "jail", "drive.blk")
	if err := os.MkdirAll(filepath.Dir(jailLink), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(drive.Path, jailLink); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "member-a"); err != nil {
		t.Fatalf("read with jailer link failed: %v", err)
	}
	if _, err := store.ReadAt(ctx, "member-a", make([]byte, 1), 0); err != nil {
		t.Fatalf("io with jailer link failed: %v", err)
	}
	// A linked current artifact cannot be wiped securely, so removal must
	// refuse until the jail (and its alias) is gone.
	if err := store.Remove(ctx, "member-a"); !errors.Is(err, ErrOwnership) {
		t.Fatalf("removal of aliased artifact = %v, want ErrOwnership", err)
	}
	// Transitions proceed while attached: the write supersedes the
	// jail-linked generation, and only the jail's own link keeps that
	// superseded inode alive until the guest stops.
	if _, err := store.WriteAt(ctx, "member-a", []byte("x"), 0); err != nil {
		t.Fatalf("write transition with jailer link failed: %v", err)
	}
	if _, err := store.Checksum(ctx, "member-a"); err != nil {
		t.Fatalf("checksum with jailer link failed: %v", err)
	}
	if err := store.Remove(ctx, "member-a"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(jailLink); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "member-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed drive state = %v, want ErrNotFound", err)
	}
}
