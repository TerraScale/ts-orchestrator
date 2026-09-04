package residency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/control/placement"
)

type testLockStore struct {
	lock  *placement.PlacementLock
	loads int
}

func (s *testLockStore) LoadPlacementLock(context.Context, string) (*placement.PlacementLock, error) {
	s.loads++
	return copyLock(s.lock), nil
}

type testMutationPort struct {
	objects map[string]ObjectIdentity
	counts  struct {
		bootstrap, repair, backup, restore, export, branch, regionChange int
	}
	corruptReadback bool
}

func (p *testMutationPort) store(database string, region placement.RegionCode, generation uint64, object string) (MutationReceipt, error) {
	body := []byte(database + "/" + object)
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	identity := ObjectIdentity{Digest: digest, Size: int64(len(body)), ETag: "etag-" + object, Version: "version-1"}
	p.objects[region.Value()+"/backups/"+object] = identity
	return MutationReceipt{
		DatabaseID: database, Region: region, PlacementGeneration: generation,
		Bucket: "backups", ObjectKey: object, Digest: identity.Digest, Size: identity.Size,
		ETag: identity.ETag, Version: identity.Version,
	}, nil
}

func (p *testMutationPort) Bootstrap(_ context.Context, request BootstrapRequest) (MutationReceipt, error) {
	p.counts.bootstrap++
	return p.store(request.DatabaseID, request.TargetRegion, request.PlacementGeneration, "database/live.sqlite")
}

func (p *testMutationPort) Repair(_ context.Context, request RepairRequest) (MutationReceipt, error) {
	p.counts.repair++
	return p.store(request.DatabaseID, request.TargetRegion, request.PlacementGeneration, "database/repaired.sqlite")
}

func (p *testMutationPort) Backup(_ context.Context, request BackupRequest) (MutationReceipt, error) {
	p.counts.backup++
	return p.store(request.DatabaseID, request.TargetRegion, request.PlacementGeneration, "backups/daily.sqlite")
}

func (p *testMutationPort) Restore(_ context.Context, request RestoreRequest) (MutationReceipt, error) {
	p.counts.restore++
	return p.store(request.DatabaseID, request.TargetRegion, request.PlacementGeneration, "restores/scratch.sqlite")
}

func (p *testMutationPort) Export(_ context.Context, request ExportRequest) (MutationReceipt, error) {
	p.counts.export++
	return p.store(request.DatabaseID, request.TargetRegion, request.PlacementGeneration, "exports/snapshot.ndjson")
}

func (p *testMutationPort) Branch(_ context.Context, request BranchRequest) (MutationReceipt, error) {
	p.counts.branch++
	return p.store(request.DatabaseID, request.TargetRegion, request.PlacementGeneration, "branches/scratch.sqlite")
}

func (p *testMutationPort) ChangeRegion(_ context.Context, request RegionChangeRequest) (MutationReceipt, error) {
	p.counts.regionChange++
	return p.store(request.DatabaseID, request.TargetRegion, request.PlacementGeneration, "database/region-copy.sqlite")
}

func (p *testMutationPort) HeadMutation(_ context.Context, region placement.RegionCode, bucket, object string) (ObjectIdentity, bool, error) {
	identity, found := p.objects[region.Value()+"/"+bucket+"/"+object]
	if p.corruptReadback && found {
		identity.Size++
	}
	return identity, found, nil
}

func newTestCoordinator(t *testing.T) (*Coordinator, *testLockStore, *testMutationPort) {
	t.Helper()
	lock, err := placement.NewExplicitPlacementLock([]placement.RegionCode{placement.RegionCodeGru, placement.RegionCodeFra}, 1)
	if err != nil {
		t.Fatal(err)
	}
	locks := &testLockStore{lock: lock}
	port := &testMutationPort{objects: map[string]ObjectIdentity{}}
	coordinator, err := NewCoordinator(locks, port, Ports{
		Bootstrap: port, Repair: port, Backup: port, Restore: port,
		Export: port, Branch: port, RegionChange: port,
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, locks, port
}

func TestCoordinatorRunsEveryTypedMutationBehindPersistedLock(t *testing.T) {
	coordinator, locks, port := newTestCoordinator(t)
	ctx := context.Background()
	if _, err := coordinator.Bootstrap(ctx, BootstrapRequest{DatabaseID: "db-1", TargetRegion: placement.RegionCodeGru, PlacementGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Repair(ctx, RepairRequest{DatabaseID: "db-1", SourceRegion: placement.RegionCodeGru, TargetRegion: placement.RegionCodeGru, PlacementGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Backup(ctx, BackupRequest{DatabaseID: "db-1", SourceRegion: placement.RegionCodeGru, TargetRegion: placement.RegionCodeFra, PlacementGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Restore(ctx, RestoreRequest{DatabaseID: "db-1", BackupRegion: placement.RegionCodeFra, TargetRegion: placement.RegionCodeGru, PlacementGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Export(ctx, ExportRequest{DatabaseID: "db-1", SourceRegion: placement.RegionCodeGru, TargetRegion: placement.RegionCodeFra, PlacementGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Branch(ctx, BranchRequest{DatabaseID: "db-1", SourceRegion: placement.RegionCodeGru, TargetRegion: placement.RegionCodeGru, PlacementGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ChangeRegion(ctx, RegionChangeRequest{DatabaseID: "db-1", SourceRegion: placement.RegionCodeGru, TargetRegion: placement.RegionCodeFra, PlacementGeneration: 1, UpdatedLock: locks.lock}); err != nil {
		t.Fatal(err)
	}
	if locks.loads != 7 {
		t.Fatalf("placement lock loads = %d, want one before each mutation", locks.loads)
	}
	got := port.counts
	want := struct {
		bootstrap, repair, backup, restore, export, branch, regionChange int
	}{1, 1, 1, 1, 1, 1, 1}
	if got != want {
		t.Fatalf("typed mutation calls = %+v", got)
	}
}

func TestCoordinatorRejectsOutsideRegionAndWideningBeforeMutation(t *testing.T) {
	coordinator, locks, port := newTestCoordinator(t)
	_, err := coordinator.Backup(context.Background(), BackupRequest{
		DatabaseID: "db-1", SourceRegion: placement.RegionCodeGru,
		TargetRegion: placement.RegionCodeSfo, PlacementGeneration: 1,
	})
	if !errors.Is(err, ErrRegionOutsideLock) || port.counts.backup != 0 {
		t.Fatalf("outside backup error = %v, calls=%d", err, port.counts.backup)
	}
	widened, err := placement.NewExplicitPlacementLock(
		[]placement.RegionCode{placement.RegionCodeGru, placement.RegionCodeFra, placement.RegionCodeSfo}, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = coordinator.ChangeRegion(context.Background(), RegionChangeRequest{
		DatabaseID: "db-1", SourceRegion: placement.RegionCodeGru,
		TargetRegion: placement.RegionCodeFra, PlacementGeneration: 1, UpdatedLock: widened,
	})
	if !errors.Is(err, ErrLockMismatch) || port.counts.regionChange != 0 {
		t.Fatalf("widening error = %v, calls=%d", err, port.counts.regionChange)
	}
	if locks.loads != 2 {
		t.Fatalf("lock loads = %d, want both attempts admitted against durable state", locks.loads)
	}
}

func TestCoordinatorRejectsReceiptWithoutMatchingProviderReadback(t *testing.T) {
	coordinator, _, port := newTestCoordinator(t)
	port.corruptReadback = true
	_, err := coordinator.Bootstrap(context.Background(), BootstrapRequest{
		DatabaseID: "db-1", TargetRegion: placement.RegionCodeGru, PlacementGeneration: 1,
	})
	if !errors.Is(err, ErrMutationUnverified) {
		t.Fatalf("corrupt readback error = %v", err)
	}
}

func TestCoordinatorRejectsIncompleteProductionComposition(t *testing.T) {
	coordinator, locks, port := newTestCoordinator(t)
	_ = coordinator
	_, err := NewCoordinator(locks, port, Ports{Bootstrap: port})
	if !errors.Is(err, ErrProductionDependency) {
		t.Fatalf("incomplete composition error = %v", err)
	}
	if _, err := coordinator.Bootstrap(nil, BootstrapRequest{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid request error = %v", err)
	}
}
