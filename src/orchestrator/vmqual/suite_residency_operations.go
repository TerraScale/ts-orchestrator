package vmqual

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/control/placement"
	"terrascale.tech/orchestrator/src/orchestrator/residency"
)

const localPlacementDatabaseID = "qualification-residency"

type localPlacementLockStore struct {
	objects *localOperationsObjectStore
}

func (s *localPlacementLockStore) save(ctx context.Context, database string, lock *placement.PlacementLock) error {
	object := localPlacementLockObject(database)
	if raw, found, err := s.objects.get(ctx, operationsControlRegion, operationsControlBucket, object); err != nil {
		return err
	} else if found {
		persisted, err := decodePlacementLock(raw)
		if err != nil || !samePlacementLock(lock, persisted) {
			return errors.New("vmqual: refusing to replace the persisted placement lock")
		}
		return nil
	}
	encoded, err := encodePlacementLock(lock)
	if err != nil {
		return err
	}
	if err := s.objects.put(ctx, operationsControlRegion, operationsControlBucket, object, encoded); err != nil {
		return err
	}
	persisted, err := s.LoadPlacementLock(ctx, database)
	if err != nil {
		return err
	}
	if !samePlacementLock(lock, persisted) {
		return errors.New("vmqual: persisted placement lock changed during creation")
	}
	return nil
}

func (s *localPlacementLockStore) LoadPlacementLock(ctx context.Context, database string) (*placement.PlacementLock, error) {
	raw, found, err := s.objects.get(ctx, operationsControlRegion, operationsControlBucket, localPlacementLockObject(database))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("vmqual: persisted placement lock is missing")
	}
	return decodePlacementLock(raw)
}

func localPlacementLockObject(database string) string {
	return "placement-locks/" + database + ".json"
}

// localResidencyMutationPort is the persistent local implementation of all
// production mutation ports. Each method copies database bytes into the
// object that operation owns and returns the provider identity from HEAD.
type localResidencyMutationPort struct {
	objects   *localOperationsObjectStore
	seed      []byte
	mutations int
}

func (p *localResidencyMutationPort) Bootstrap(ctx context.Context, request residency.BootstrapRequest) (residency.MutationReceipt, error) {
	return p.write(ctx, request.DatabaseID, request.TargetRegion, request.PlacementGeneration,
		localLiveDatabaseObject(request.DatabaseID, request.TargetRegion), p.seed)
}

func (p *localResidencyMutationPort) Repair(ctx context.Context, request residency.RepairRequest) (residency.MutationReceipt, error) {
	return p.copy(ctx, request.DatabaseID, request.SourceRegion, localLiveDatabaseObject(request.DatabaseID, request.SourceRegion),
		request.TargetRegion, request.PlacementGeneration, localRepairObject(request.DatabaseID, request.TargetRegion))
}

func (p *localResidencyMutationPort) Backup(ctx context.Context, request residency.BackupRequest) (residency.MutationReceipt, error) {
	return p.copy(ctx, request.DatabaseID, request.SourceRegion, localLiveDatabaseObject(request.DatabaseID, request.SourceRegion),
		request.TargetRegion, request.PlacementGeneration, localBackupObject(request.DatabaseID))
}

func (p *localResidencyMutationPort) Restore(ctx context.Context, request residency.RestoreRequest) (residency.MutationReceipt, error) {
	return p.copy(ctx, request.DatabaseID, request.BackupRegion, localBackupObject(request.DatabaseID),
		request.TargetRegion, request.PlacementGeneration, localRestoreObject(request.DatabaseID))
}

func (p *localResidencyMutationPort) Export(ctx context.Context, request residency.ExportRequest) (residency.MutationReceipt, error) {
	return p.copy(ctx, request.DatabaseID, request.SourceRegion, localLiveDatabaseObject(request.DatabaseID, request.SourceRegion),
		request.TargetRegion, request.PlacementGeneration, localExportObject(request.DatabaseID))
}

func (p *localResidencyMutationPort) Branch(ctx context.Context, request residency.BranchRequest) (residency.MutationReceipt, error) {
	return p.copy(ctx, request.DatabaseID, request.SourceRegion, localLiveDatabaseObject(request.DatabaseID, request.SourceRegion),
		request.TargetRegion, request.PlacementGeneration, localBranchObject(request.DatabaseID))
}

func (p *localResidencyMutationPort) ChangeRegion(ctx context.Context, request residency.RegionChangeRequest) (residency.MutationReceipt, error) {
	return p.copy(ctx, request.DatabaseID, request.SourceRegion, localLiveDatabaseObject(request.DatabaseID, request.SourceRegion),
		request.TargetRegion, request.PlacementGeneration, localLiveDatabaseObject(request.DatabaseID, request.TargetRegion))
}

func (p *localResidencyMutationPort) copy(ctx context.Context, database string, sourceRegion placement.RegionCode, sourceObject string, targetRegion placement.RegionCode, generation uint64, targetObject string) (residency.MutationReceipt, error) {
	body, found, err := p.objects.get(ctx, localRegionName(sourceRegion), operationsBackupBucket, sourceObject)
	if err != nil {
		return residency.MutationReceipt{}, err
	}
	if !found || len(body) == 0 {
		return residency.MutationReceipt{}, errors.New("vmqual: residency mutation source is missing")
	}
	return p.write(ctx, database, targetRegion, generation, targetObject, body)
}

func (p *localResidencyMutationPort) write(ctx context.Context, database string, region placement.RegionCode, generation uint64, object string, body []byte) (residency.MutationReceipt, error) {
	regionName := localRegionName(region)
	if err := p.objects.put(ctx, regionName, operationsBackupBucket, object, body); err != nil {
		return residency.MutationReceipt{}, err
	}
	identity, found, err := p.objects.head(ctx, regionName, operationsBackupBucket, object)
	if err != nil {
		return residency.MutationReceipt{}, err
	}
	if !found {
		return residency.MutationReceipt{}, errors.New("vmqual: residency mutation is not visible after write")
	}
	p.mutations++
	return residency.MutationReceipt{
		DatabaseID: database, Region: region, PlacementGeneration: generation,
		Bucket: operationsBackupBucket, ObjectKey: object, Digest: identity.Digest,
		Size: identity.Size, ETag: identity.ETag, Version: identity.Version,
	}, nil
}

func (p *localResidencyMutationPort) HeadMutation(ctx context.Context, region placement.RegionCode, bucket, object string) (residency.ObjectIdentity, bool, error) {
	identity, found, err := p.objects.head(ctx, localRegionName(region), bucket, object)
	return residency.ObjectIdentity{
		Digest: identity.Digest, Size: identity.Size, ETag: identity.ETag, Version: identity.Version,
	}, found, err
}

func localRegionName(region placement.RegionCode) string {
	return strings.ToLower(region.Value())
}

func localLiveDatabaseObject(database string, region placement.RegionCode) string {
	return "databases/" + database + "/regions/" + localRegionName(region) + "/live.sqlite"
}

func localRepairObject(database string, region placement.RegionCode) string {
	return "databases/" + database + "/regions/" + localRegionName(region) + "/repaired.sqlite"
}

func localBackupObject(database string) string {
	return "backups/" + database + "/daily.sqlite"
}

func localRestoreObject(database string) string {
	return "restores/" + database + "/scratch.sqlite"
}

func localExportObject(database string) string {
	return "exports/" + database + "/snapshot.ndjson"
}

func localBranchObject(database string) string {
	return "branches/" + database + "/scratch.sqlite"
}

func (c *LocalOperationsContract) qualifyPlacementMutations(ctx context.Context) (PlacementOperationsResult, error) {
	var result PlacementOperationsResult
	if err := c.ready(ctx); err != nil {
		return result, err
	}
	if err := c.ensureDeclaredBuckets(ctx); err != nil {
		return result, err
	}
	requested, err := placement.NewExplicitPlacementLock([]placement.RegionCode{placement.RegionCodeGru, placement.RegionCodeFra}, 1)
	if err != nil {
		return result, err
	}
	resolved, err := placement.ResolvePlacementLock(requested, operationsPlacementCatalog())
	if err != nil {
		return result, err
	}
	decision := placement.DatabasePlacementEvaluator.Evaluate(operationsPlacementRequest(resolved), operationsPlacementCatalog())
	if !decision.Accepted() || decision.EffectiveLock == nil {
		return result, fmt.Errorf("vmqual: production placement contract rejected qualification intent: %+v", decision.Errors)
	}
	lock := decision.EffectiveLock
	locks := &localPlacementLockStore{objects: c.objects}
	if err := locks.save(ctx, localPlacementDatabaseID, lock); err != nil {
		return result, err
	}
	mutations := &localResidencyMutationPort{
		objects: c.objects,
		seed:    []byte("{\"rows\":[{\"id\":\"resident-1\"},{\"id\":\"resident-2\"}]}\n"),
	}
	coordinator, err := residency.NewCoordinator(locks, mutations, residency.Ports{
		Bootstrap: mutations, Repair: mutations, Backup: mutations, Restore: mutations,
		Export: mutations, Branch: mutations, RegionChange: mutations,
	})
	if err != nil {
		return result, err
	}

	result.Bootstrap, err = coordinator.Bootstrap(ctx, residency.BootstrapRequest{
		DatabaseID: localPlacementDatabaseID, TargetRegion: placement.RegionCodeGru, PlacementGeneration: lock.Generation,
	})
	if err != nil {
		return result, fmt.Errorf("vmqual: resident bootstrap failed: %w", err)
	}
	result.Repair, err = coordinator.Repair(ctx, residency.RepairRequest{
		DatabaseID: localPlacementDatabaseID, SourceRegion: placement.RegionCodeGru,
		TargetRegion: placement.RegionCodeGru, PlacementGeneration: lock.Generation,
	})
	if err != nil {
		return result, fmt.Errorf("vmqual: resident repair failed: %w", err)
	}
	result.Backup, err = coordinator.Backup(ctx, residency.BackupRequest{
		DatabaseID: localPlacementDatabaseID, SourceRegion: placement.RegionCodeGru,
		TargetRegion: placement.RegionCodeFra, PlacementGeneration: lock.Generation,
	})
	if err != nil {
		return result, fmt.Errorf("vmqual: resident backup failed: %w", err)
	}
	result.Restore, err = coordinator.Restore(ctx, residency.RestoreRequest{
		DatabaseID: localPlacementDatabaseID, BackupRegion: placement.RegionCodeFra,
		TargetRegion: placement.RegionCodeGru, PlacementGeneration: lock.Generation,
	})
	if err != nil {
		return result, fmt.Errorf("vmqual: resident restore failed: %w", err)
	}
	result.Export, err = coordinator.Export(ctx, residency.ExportRequest{
		DatabaseID: localPlacementDatabaseID, SourceRegion: placement.RegionCodeGru,
		TargetRegion: placement.RegionCodeFra, PlacementGeneration: lock.Generation,
	})
	if err != nil {
		return result, fmt.Errorf("vmqual: resident export failed: %w", err)
	}
	result.Branch, err = coordinator.Branch(ctx, residency.BranchRequest{
		DatabaseID: localPlacementDatabaseID, SourceRegion: placement.RegionCodeGru,
		TargetRegion: placement.RegionCodeGru, PlacementGeneration: lock.Generation,
	})
	if err != nil {
		return result, fmt.Errorf("vmqual: resident branch failed: %w", err)
	}
	result.RegionChange, err = coordinator.ChangeRegion(ctx, residency.RegionChangeRequest{
		DatabaseID: localPlacementDatabaseID, SourceRegion: placement.RegionCodeGru,
		TargetRegion: placement.RegionCodeFra, PlacementGeneration: lock.Generation, UpdatedLock: lock,
	})
	if err != nil {
		return result, fmt.Errorf("vmqual: resident Region change failed: %w", err)
	}

	widened, err := placement.NewExplicitPlacementLock(
		[]placement.RegionCode{placement.RegionCodeGru, placement.RegionCodeFra, placement.RegionCodeSfo}, 2,
	)
	if err != nil {
		return result, err
	}
	_, wideningErr := coordinator.ChangeRegion(ctx, residency.RegionChangeRequest{
		DatabaseID: localPlacementDatabaseID, SourceRegion: placement.RegionCodeGru,
		TargetRegion: placement.RegionCodeFra, PlacementGeneration: lock.Generation, UpdatedLock: widened,
	})
	result.WideningRejected = errors.Is(wideningErr, residency.ErrLockMismatch) && mutations.mutations == 7
	if !result.WideningRejected {
		return result, fmt.Errorf("vmqual: placement lock widening was not rejected before mutation: %w", wideningErr)
	}

	receipts := []residency.MutationReceipt{
		result.Bootstrap, result.Repair, result.Backup, result.Restore,
		result.Export, result.Branch, result.RegionChange,
	}
	for _, receipt := range receipts {
		body, found, err := c.objects.get(ctx, localRegionName(receipt.Region), receipt.Bucket, receipt.ObjectKey)
		if err != nil || !found || !bytes.Equal(body, mutations.seed) {
			return result, fmt.Errorf("vmqual: resident database mutation %s failed persistent readback: %w", receipt.ObjectKey, err)
		}
		_, escaped, err := c.objects.head(ctx, "sfo", receipt.Bucket, receipt.ObjectKey)
		if err != nil || escaped {
			return result, fmt.Errorf("vmqual: database bytes escaped placement lock at %s: %w", receipt.ObjectKey, err)
		}
	}
	persisted, err := locks.LoadPlacementLock(ctx, localPlacementDatabaseID)
	if err != nil || !samePlacementLock(lock, persisted) {
		return result, fmt.Errorf("vmqual: placement lock did not survive mutations: %w", err)
	}
	_, escaped, err := c.objects.head(ctx, "sfo", operationsControlBucket, localPlacementLockObject(localPlacementDatabaseID))
	if err != nil || escaped {
		return result, fmt.Errorf("vmqual: placement lock itself escaped residency: %w", err)
	}
	result.Kind = string(lock.Kind)
	result.Generation = lock.Generation
	for _, region := range lock.Regions {
		result.Regions = append(result.Regions, region.Value())
	}
	if len(result.Regions) == 2 && result.Regions[0] > result.Regions[1] {
		result.Regions[0], result.Regions[1] = result.Regions[1], result.Regions[0]
	}
	result.Persistent = true
	return result, nil
}

func (r PlacementOperationsResult) mutationCount() int {
	receipts := []residency.MutationReceipt{
		r.Bootstrap, r.Repair, r.Backup, r.Restore, r.Export, r.Branch, r.RegionChange,
	}
	count := 0
	for _, receipt := range receipts {
		if receipt.ObjectKey != "" && receipt.Digest != "" && receipt.Size > 0 {
			count++
		}
	}
	return count
}

var (
	_ residency.PlacementLockStore = (*localPlacementLockStore)(nil)
	_ residency.BootstrapPort      = (*localResidencyMutationPort)(nil)
	_ residency.RepairPort         = (*localResidencyMutationPort)(nil)
	_ residency.BackupPort         = (*localResidencyMutationPort)(nil)
	_ residency.RestorePort        = (*localResidencyMutationPort)(nil)
	_ residency.ExportPort         = (*localResidencyMutationPort)(nil)
	_ residency.BranchPort         = (*localResidencyMutationPort)(nil)
	_ residency.RegionChangePort   = (*localResidencyMutationPort)(nil)
	_ residency.MutationInspector  = (*localResidencyMutationPort)(nil)
)
