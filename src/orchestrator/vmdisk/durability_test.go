package vmdisk

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPlanVerifyAndTerminalCleanupAreRunOwned(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	root := filepath.Join(parent, "store")
	planned, err := PlanPaths(root, "member-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PlanPaths mutated the root: %v", err)
	}
	store, err := New(Config{Root: root, RunID: "qualification-run"})
	if err != nil {
		t.Fatal(err)
	}
	drive, err := store.Create(ctx, "member-a", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if drive.Path != planned.Artifact {
		t.Fatalf("created artifact = %q, planned = %q", drive.Path, planned.Artifact)
	}
	if err := VerifyPaths(planned, store.RunID(), "member-a"); err != nil {
		t.Fatalf("verify generation one: %v", err)
	}
	if _, err := store.WriteAt(ctx, "member-a", []byte("new generation"), 0); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPaths(planned, store.RunID(), "member-a"); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("stale journaled artifact verification = %v", err)
	}
	current, err := VerifyDrive(root, store.RunID(), "member-a")
	if err != nil {
		t.Fatal(err)
	}
	if current.Artifact == planned.Artifact || current.DriveDir != planned.DriveDir || current.Metadata != planned.Metadata || current.Ownership != planned.Ownership {
		t.Fatalf("current paths = %+v, initial = %+v", current, planned)
	}
	stale, err := New(Config{Root: root, RunID: store.RunID()})
	if err != nil {
		t.Fatalf("open second store handle: %v", err)
	}
	if err := store.CloseAndRemove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("terminal store root remains: %v", err)
	}
	if _, err := store.Get(ctx, "member-a"); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed store Get = %v", err)
	}
	reopened, err := New(Config{Root: root, RunID: "qualification-run"})
	if err != nil {
		t.Fatalf("reuse removed root: %v", err)
	}
	if _, err := reopened.Create(ctx, "replacement", 4096); err != nil {
		t.Fatalf("create replacement drive: %v", err)
	}
	if _, err := stale.Get(ctx, "replacement"); !errors.Is(err, ErrOwnership) {
		t.Fatalf("stale store handle crossed into replacement root: %v", err)
	}
	if err := reopened.CloseAndRemove(ctx); err != nil {
		t.Fatalf("remove reused root: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("terminal cleanup left entries: %v, err=%v", entries, err)
	}
}

func TestDeterministicTombstoneCrashReplay(t *testing.T) {
	ctx := context.Background()
	crashAfterDetach := func(t *testing.T, root, runID string) (*Store, StoreIdentity) {
		t.Helper()
		store, err := New(Config{Root: root, RunID: runID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Create(ctx, "disk", 4096); err != nil {
			t.Fatal(err)
		}
		identity := store.Identity()
		store.hooks.afterRootRename = func(StoreIdentity) error { return syscall.EIO }
		if err := store.CloseAndRemove(ctx); !errors.Is(err, syscall.EIO) {
			t.Fatalf("detach crash = %v", err)
		}
		if _, err := os.Lstat(identity.Root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("detached root remains: %v", err)
		}
		if info, err := os.Lstat(identity.Tombstone); err != nil || !info.IsDir() {
			t.Fatalf("deterministic tombstone = %v, err=%v", info, err)
		}
		return store, identity
	}

	t.Run("closed handle retry", func(t *testing.T) {
		parent := t.TempDir()
		store, identity := crashAfterDetach(t, filepath.Join(parent, "store"), "retry-run")
		if err := store.CloseAndRemove(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(identity.Tombstone); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retried tombstone remains: %v", err)
		}
	})

	t.Run("public replay", func(t *testing.T) {
		parent := t.TempDir()
		_, identity := crashAfterDetach(t, filepath.Join(parent, "store"), "public-replay-run")
		if err := RemoveStore(ctx, identity); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(identity.Tombstone); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("public replay tombstone remains: %v", err)
		}
	})

	t.Run("explicit identity recovers before reuse", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "store")
		_, identity := crashAfterDetach(t, root, "explicit-reuse-run")
		reopened, err := New(Config{Root: root, RunID: identity.RunID, Ownership: &identity.Ownership})
		if err != nil {
			t.Fatal(err)
		}
		if reopened.Identity() != identity {
			t.Fatalf("reopened identity = %+v, want %+v", reopened.Identity(), identity)
		}
		if _, err := os.Lstat(identity.Tombstone); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovered tombstone remains: %v", err)
		}
		if err := reopened.CloseAndRemove(ctx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("automatic run refuses pending identity", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "store")
		_, identity := crashAfterDetach(t, root, "automatic-block-run")
		if _, err := New(Config{Root: root}); !errors.Is(err, ErrCleanupPending) {
			t.Fatalf("automatic reuse with tombstone = %v", err)
		}
		if err := RemoveStore(ctx, identity); err != nil {
			t.Fatal(err)
		}
	})
}

func TestOwnedVerificationUsesTrustedIdentity(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "store")
	store, err := New(Config{Root: root, RunID: "owned-verify-run"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "disk", 4096); err != nil {
		t.Fatal(err)
	}
	identity := store.Identity()
	paths, err := VerifyDriveOwned(identity, "disk")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPathsOwned(paths, identity, "disk"); err != nil {
		t.Fatal(err)
	}
	wrong := identity
	wrong.Ownership.UID++
	wrong, err = PlanStoreIdentity(wrong.Root, wrong.RunID, wrong.Ownership)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDriveOwned(wrong, "disk"); !errors.Is(err, ErrOwnership) {
		t.Fatalf("wrong trusted ownership = %v", err)
	}
	if err := store.CloseAndRemove(ctx); err != nil {
		t.Fatal(err)
	}

	if os.Geteuid() != 0 {
		return
	}
	nonRoot := Ownership{UID: 65534, GID: 65534}
	nonRootRoot := filepath.Join(t.TempDir(), "jailer-store")
	jailerStore, err := New(Config{Root: nonRootRoot, RunID: "jailer-owned-run", Ownership: &nonRoot})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jailerStore.Create(ctx, "disk", 4096); err != nil {
		t.Fatal(err)
	}
	jailerIdentity := jailerStore.Identity()
	if _, err := VerifyDriveOwned(jailerIdentity, "disk"); err != nil {
		t.Fatalf("verify non-current ownership: %v", err)
	}
	if _, err := VerifyDrive(nonRootRoot, jailerIdentity.RunID, "disk"); !errors.Is(err, ErrOwnership) {
		t.Fatalf("legacy verification inferred non-current owner: %v", err)
	}
	if err := jailerStore.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := RemoveStore(ctx, jailerIdentity); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRejectsHardLinkedLockWithoutChangingTarget(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "store")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "target")
	if err := os.WriteFile(target, []byte("do not alter"), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(root, lockFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Root: root, RunID: "hard-link-run"}); !errors.Is(err, ErrOwnership) {
		t.Fatalf("hard-linked lock = %v", err)
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() || string(mustReadFile(t, target)) != "do not alter" {
		t.Fatalf("lock target changed: before=%v after=%v", before.Mode().Perm(), after.Mode().Perm())
	}
}

func TestCleanupPreflightsForeignEntries(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := New(Config{Root: root, RunID: "cleanup-run"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "a-drive", 4096); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "drives", "z-foreign")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Cleanup(ctx); !errors.Is(err, ErrOwnership) {
		t.Fatalf("cleanup with foreign entry = %v", err)
	}
	if _, err := store.Get(ctx, "a-drive"); err != nil {
		t.Fatalf("preflight failure removed owned drive: %v", err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	foreign = filepath.Join(root, "foreign")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseAndRemove(ctx); !errors.Is(err, ErrOwnership) {
		t.Fatalf("terminal cleanup with foreign entry = %v", err)
	}
	if _, err := store.Get(ctx, "a-drive"); err != nil {
		t.Fatalf("terminal preflight failure removed owned drive: %v", err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseAndRemove(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupRejectsDirectoryReplacementAfterPreflight(t *testing.T) {
	ctx := context.Background()
	for _, replacement := range []string{"symlink", "directory"} {
		t.Run(replacement, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "store")
			store, err := New(Config{Root: root, RunID: "swap-" + replacement + "-run"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Create(ctx, "disk", 4096); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "drives", "disk")
			detached := filepath.Join(parent, "detached-drive")
			sentinel := filepath.Join(parent, "sentinel")
			if err := os.Mkdir(sentinel, 0o700); err != nil {
				t.Fatal(err)
			}
			sentinelFile := filepath.Join(sentinel, "keep")
			if err := os.WriteFile(sentinelFile, []byte("do not remove"), 0o600); err != nil {
				t.Fatal(err)
			}
			store.hooks.beforeManagedCleanup = func(path string) error {
				store.hooks.beforeManagedCleanup = nil
				if path != target {
					return nil
				}
				if err := os.Rename(target, detached); err != nil {
					return err
				}
				if replacement == "symlink" {
					return os.Symlink(sentinel, target)
				}
				return os.Rename(sentinel, target)
			}
			if err := store.Cleanup(ctx); err == nil {
				t.Fatal("cleanup accepted a directory replacement")
			}
			currentSentinel := sentinelFile
			if replacement == "directory" {
				currentSentinel = filepath.Join(target, "keep")
			}
			if got := string(mustReadFile(t, currentSentinel)); got != "do not remove" {
				t.Fatalf("sentinel contents = %q", got)
			}
			if replacement == "symlink" {
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Rename(target, sentinel); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(detached, target); err != nil {
				t.Fatal(err)
			}
			if err := store.CloseAndRemove(ctx); err != nil {
				t.Fatal(err)
			}
			if got := string(mustReadFile(t, sentinelFile)); got != "do not remove" {
				t.Fatalf("sentinel after valid cleanup = %q", got)
			}
		})
	}
}

func TestMountAndDeviceIdentityChecks(t *testing.T) {
	base := unix.Statx_t{Ino: 1, Mnt_id: 2, Dev_major: 3, Dev_minor: 4, Mode: unix.S_IFREG}
	for name, mutate := range map[string]func(*unix.Statx_t){
		"mount":        func(stat *unix.Statx_t) { stat.Mnt_id++ },
		"device major": func(stat *unix.Statx_t) { stat.Dev_major++ },
		"device minor": func(stat *unix.Statx_t) { stat.Dev_minor++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if sameStatxIdentity(base, changed) {
				t.Fatalf("identity ignored changed %s", name)
			}
		})
	}

	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "store")
	store, err := New(Config{Root: root, RunID: "bind-mount-run"})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := unix.Mount(source, filepath.Join(root, "drives"), "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOSYS) {
			if err := store.CloseAndRemove(ctx); err != nil {
				t.Fatal(err)
			}
			t.Skipf("bind mounts unavailable: %v", err)
		}
		t.Fatal(err)
	}
	mounted := true
	defer func() {
		if mounted {
			_ = unix.Unmount(filepath.Join(root, "drives"), unix.MNT_DETACH)
		}
	}()
	if _, err := store.Usage(ctx); !errors.Is(err, ErrOwnership) {
		t.Fatalf("live store accepted bind-mounted drives directory: %v", err)
	}
	if _, err := New(Config{Root: root, RunID: store.RunID()}); !errors.Is(err, ErrOwnership) {
		t.Fatalf("bind-mounted drives directory = %v", err)
	}
	if err := unix.Unmount(filepath.Join(root, "drives"), 0); err != nil {
		t.Fatal(err)
	}
	mounted = false
	if err := store.CloseAndRemove(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataEncodingMustBeCanonical(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := New(Config{Root: root, RunID: "canonical-run"})
	if err != nil {
		t.Fatal(err)
	}
	drive, err := store.Create(ctx, "disk", 4096)
	if err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(filepath.Dir(drive.Path), metadataName)
	data := mustReadFile(t, metadataPath)
	if err := os.WriteFile(metadataPath, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDrive(root, store.RunID(), "disk"); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("noncanonical metadata verification = %v", err)
	}
}

func TestNextBootContractDoesNotClaimLiveGuestMutation(t *testing.T) {
	ctx := context.Background()
	store, err := New(Config{Root: t.TempDir(), RunID: "next-boot-run"})
	if err != nil {
		t.Fatal(err)
	}
	drive, err := store.Create(ctx, "disk", 4096)
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Checksum(ctx, "disk")
	if err != nil {
		t.Fatal(err)
	}
	fill, err := store.PrepareFaultPlan(ctx, "disk", FaultPlan{FillAll: true})
	if err != nil {
		t.Fatal(err)
	}
	afterFill, err := store.Checksum(ctx, "disk")
	if err != nil {
		t.Fatal(err)
	}
	if afterFill != before || !fill.Plan.RequiresStoppedGuest || fill.Plan.Activation != ActivationNextBoot || !fill.Plan.RequiresGuestFilesystemFill || !fill.Plan.FillToENOSPC || fill.Plan.FillBytes != drive.Size {
		t.Fatalf("fill plan = %+v, checksum before=%s after=%s", fill.Plan, before, afterFill)
	}
	if err := store.ClearFaults(ctx, "disk"); err != nil {
		t.Fatal(err)
	}
	readOnly, err := store.PrepareFaultPlan(ctx, "disk", FaultPlan{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !readOnly.Plan.ReadOnly || readOnly.Plan.Activation != ActivationNextBoot {
		t.Fatalf("read-only plan = %+v", readOnly.Plan)
	}
	info, err := os.Stat(readOnly.Plan.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("read-only intent changed host artifact mode: %v", info.Mode())
	}
	if err := store.ClearFaults(ctx, "disk"); err != nil {
		t.Fatal(err)
	}
	ioFailure, err := store.PrepareFaultPlan(ctx, "disk", FaultPlan{IOFailure: true})
	if err != nil {
		t.Fatal(err)
	}
	if !ioFailure.Plan.IOFailure || !ioFailure.Plan.RequiresRuntimeFaultAdapter {
		t.Fatalf("I/O-failure plan = %+v", ioFailure.Plan)
	}
	if err := store.ClearFaults(ctx, "disk"); err != nil {
		t.Fatal(err)
	}
	detached, err := store.PrepareAttachment(ctx, "disk", false)
	if err != nil {
		t.Fatal(err)
	}
	if detached.Plan.Attachment != AttachmentDetached || detached.Plan.Path != "" || detached.Plan.SHA256 != "" {
		t.Fatalf("detached plan exposes an artifact: %+v", detached.Plan)
	}
	if _, err := store.PrepareAttachment(ctx, "disk", true); err != nil {
		t.Fatal(err)
	}
	expanded, err := store.PrepareExpansion(ctx, "disk", 8192)
	if err != nil {
		t.Fatal(err)
	}
	if !expanded.Plan.RequiresGuestFilesystemGrow || expanded.Plan.Transition.Kind != TransitionExpand || expanded.Plan.Transition.PreviousSize != 4096 {
		t.Fatalf("expansion plan = %+v", expanded.Plan)
	}
	if _, err := store.PrepareAttachment(ctx, "disk", false); err != nil {
		t.Fatal(err)
	}
	reattached, err := store.PrepareAttachment(ctx, "disk", true)
	if err != nil {
		t.Fatal(err)
	}
	if !reattached.Plan.RequiresGuestFilesystemGrow {
		t.Fatalf("attachment transition lost pending filesystem growth: %+v", reattached.Plan)
	}
	for name, plan := range map[string]FaultPlan{
		"fill-all-and-bytes":  {FillAll: true, FillBytes: 1},
		"detach-and-reattach": {Detach: true, Reattach: true},
	} {
		if _, err := store.PrepareFaultPlan(ctx, "disk", plan); !errors.Is(err, ErrInvalidFault) {
			t.Fatalf("conflicting %s plan = %v", name, err)
		}
	}
	oldPath := reattached.Plan.Path
	corrupted, err := store.PrepareFaultPlan(ctx, "disk", FaultPlan{Corruptions: []Corruption{{Offset: 64, Length: 4, Pattern: 0x7e}}})
	if err != nil {
		t.Fatal(err)
	}
	if corrupted.Plan.Path == oldPath || corrupted.Plan.Transition.Kind != TransitionCorrupt || len(corrupted.Plan.Transition.Corruptions) != 1 {
		t.Fatalf("corruption plan = %+v", corrupted.Plan)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("superseded artifact remains: %v", err)
	}
	got := make([]byte, 4)
	if _, err := store.ReadAt(ctx, "disk", got, 64); err != nil || !bytes.Equal(got, []byte{0x7e, 0x7e, 0x7e, 0x7e}) {
		t.Fatalf("materialized corruption = %x, err=%v", got, err)
	}
}

func TestQuotasIncludeSnapshotsAndDeduplicateIdenticalSnapshot(t *testing.T) {
	ctx := context.Background()
	store, err := New(Config{Root: t.TempDir(), RunID: "quota-run", MaxBytes: 40, MaxDrives: 1, MaxSnapshots: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "disk", 8); err != nil {
		t.Fatal(err)
	}
	first, err := store.Snapshot(ctx, "disk")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Snapshot(ctx, "disk")
	if err != nil || second.ID != first.ID {
		t.Fatalf("identical snapshot = %+v, err=%v", second, err)
	}
	if _, err := store.Create(ctx, "second", 1); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("drive-count quota = %v", err)
	}
	if _, err := store.WriteAt(ctx, "disk", []byte{1}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Snapshot(ctx, "disk"); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("snapshot-count quota = %v", err)
	}
	if err := store.Expand(ctx, "disk", 24); err != nil {
		t.Fatal(err)
	}
	if err := store.Expand(ctx, "disk", 25); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("byte quota = %v", err)
	}
	usage, err := store.Usage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if usage != (Usage{Bytes: 32, Drives: 1, Snapshots: 1}) {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestCopyOnWriteQuotaIncludesPeakStagingBytes(t *testing.T) {
	ctx := context.Background()
	store, err := New(Config{Root: t.TempDir(), RunID: "peak-run", MaxBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "disk", 8); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteAt(ctx, "disk", []byte{1}, 0); err != nil {
		t.Fatalf("write at exact peak quota: %v", err)
	}
	if _, err := store.Snapshot(ctx, "disk"); err != nil {
		t.Fatal(err)
	}
	before, err := store.Get(ctx, "disk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteAt(ctx, "disk", []byte{2}, 0); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("write beyond peak quota = %v", err)
	}
	assertDriveUnchanged(t, store, before, "\x01")
}

func TestExpansionClearsFullDiskIntentAndPreservesFilledBytes(t *testing.T) {
	ctx := context.Background()
	store, err := New(Config{Root: t.TempDir(), RunID: "expand-full-run"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "disk", 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareFaultPlan(ctx, "disk", FaultPlan{FillAll: true}); err != nil {
		t.Fatal(err)
	}
	outcome, err := store.PrepareExpansion(ctx, "disk", 8192)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Plan.FillToENOSPC || outcome.Plan.FillBytes != 4096 || !outcome.Plan.RequiresGuestFilesystemGrow {
		t.Fatalf("expanded full-disk plan = %+v", outcome.Plan)
	}
	acknowledged, err := store.AcknowledgeFilesystemGrow(ctx, "disk", outcome.Plan.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if acknowledged.RequiresGuestFilesystemGrow || acknowledged.Generation != outcome.Plan.Generation+1 || acknowledged.Transition.Kind != TransitionAcknowledgeGrow {
		t.Fatalf("acknowledged expansion plan = %+v", acknowledged)
	}
	replayed, err := store.AcknowledgeFilesystemGrow(ctx, "disk", outcome.Plan.Generation)
	if err != nil || replayed.Generation != acknowledged.Generation {
		t.Fatalf("replayed expansion acknowledgment = %+v, err=%v", replayed, err)
	}
	if _, err := store.AcknowledgeFilesystemGrow(ctx, "disk", 1); !errors.Is(err, ErrDriveBusy) {
		t.Fatalf("stale expansion acknowledgment = %v", err)
	}
}

func TestLockWaitHonorsCancellation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	first, err := New(Config{Root: root, RunID: "lock-run"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Create(ctx, "disk", 4096); err != nil {
		t.Fatal(err)
	}
	second, err := New(Config{Root: root, RunID: "lock-run"})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	first.hooks.beforeCopy = func(string) error {
		close(entered)
		<-release
		return nil
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := first.WriteAt(ctx, "disk", []byte{1}, 0)
		writeDone <- err
	}()
	<-entered
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := second.Get(waitCtx, "disk"); !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		t.Fatalf("queued Get = %v", err)
	}
	close(release)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestENOSPCAndMetadataCommitFailureLeavePublishedDriveIntact(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := New(Config{
		Root:   root,
		RunID:  "enospc-run",
		Runner: FaultRunnerFunc(func(context.Context, FaultAction) error { return syscall.ENOSPC }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "disk", 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteAt(ctx, "disk", []byte("stable"), 0); err != nil {
		t.Fatal(err)
	}
	before, err := store.Get(ctx, "disk")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyFaultPlan(ctx, "disk", FaultPlan{Corruptions: []Corruption{{Offset: 0, Length: 1, Pattern: 0xff}}}); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("runner ENOSPC = %v", err)
	}
	assertDriveUnchanged(t, store, before, "stable")

	store.hooks.beforeMetadataCommit = func(string) error { return syscall.ENOSPC }
	if err := store.Expand(ctx, "disk", 8192); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("metadata ENOSPC = %v", err)
	}
	store.hooks.beforeMetadataCommit = nil
	assertDriveUnchanged(t, store, before, "stable")
	entries, err := os.ReadDir(filepath.Dir(before.Path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("failed copy-on-write leaked entries: %v", entries)
	}

	store.hooks.beforeCopy = func(string) error { return syscall.ENOSPC }
	if _, err := store.Snapshot(ctx, "disk"); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("snapshot ENOSPC = %v", err)
	}
	store.hooks.beforeCopy = nil
	usage, err := store.Usage(ctx)
	if err != nil || usage.Snapshots != 0 {
		t.Fatalf("failed snapshot usage = %+v, err=%v", usage, err)
	}
}

func TestCorruptSnapshotRestoreFailsWithoutPublishingCandidate(t *testing.T) {
	ctx := context.Background()
	store, err := New(Config{Root: t.TempDir(), RunID: "restore-run"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "disk", 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteAt(ctx, "disk", []byte("snapshot"), 0); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(ctx, "disk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteAt(ctx, "disk", []byte("current!"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(snapshot.Path, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(snapshot.Path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xff}, 0); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(snapshot.Path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Snapshot(ctx, "disk"); !errors.Is(err, ErrCorruptSnapshot) {
		t.Fatalf("corrupt deduplicated snapshot = %v", err)
	}
	if _, err := store.Usage(ctx); !errors.Is(err, ErrCorruptSnapshot) {
		t.Fatalf("corrupt snapshot usage admission = %v", err)
	}
	if _, err := New(Config{Root: store.Root(), RunID: store.RunID()}); !errors.Is(err, ErrCorruptSnapshot) {
		t.Fatalf("corrupt snapshot reopen admission = %v", err)
	}
	before, err := store.Get(ctx, "disk")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Restore(ctx, "disk", snapshot); !errors.Is(err, ErrCorruptSnapshot) {
		t.Fatalf("corrupt restore = %v", err)
	}
	assertDriveUnchanged(t, store, before, "current!")
}

func TestReopenRecoversOnlyLabelledStaleArtifactsAndRejectsMetadataCorruption(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := New(Config{Root: root, RunID: "recovery-run"})
	if err != nil {
		t.Fatal(err)
	}
	drive, err := store.Create(ctx, "disk", 4096)
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(filepath.Dir(drive.Path), artifactName(99))
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(filepath.Dir(drive.Path), jsonTemporaryPrefix+"0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "drives", stageDrivePrefix+store.RunID()+"-0123456789abcdef0123456789abcdef")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Root: root, RunID: store.RunID()}); err != nil {
		t.Fatalf("recover stale artifacts: %v", err)
	}
	for _, path := range []string{stale, temporary, stage} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale path %q remains: %v", path, err)
		}
	}

	metadataPath := filepath.Join(filepath.Dir(drive.Path), metadataName)
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"attached":true`), []byte(`"attached":false`), 1)
	if err := os.WriteFile(metadataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Root: root, RunID: store.RunID()}); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("corrupt metadata reopen = %v", err)
	}
}

func assertDriveUnchanged(t *testing.T, store *Store, before *Drive, prefix string) {
	t.Helper()
	after, err := store.Get(context.Background(), before.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != before.Generation || after.Path != before.Path || after.Size != before.Size {
		t.Fatalf("drive changed: before=%+v after=%+v", before, after)
	}
	buffer := make([]byte, len(prefix))
	if _, err := store.ReadAt(context.Background(), before.ID, buffer, 0); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != prefix {
		t.Fatalf("drive prefix = %q, want %q", buffer, prefix)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
