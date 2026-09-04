// Package residency coordinates every operation that can place database bytes
// at rest. The coordinator loads the durable placement lock before dispatching
// an operation and verifies the provider identity after the mutation returns.
package residency

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/control/placement"
)

var (
	ErrInvalidRequest       = errors.New("residency: invalid operation request")
	ErrProductionDependency = errors.New("residency: production dependency is unavailable")
	ErrLockUnavailable      = errors.New("residency: persisted placement lock is unavailable")
	ErrLockMismatch         = errors.New("residency: placement lock does not match persisted state")
	ErrRegionOutsideLock    = errors.New("residency: Region is outside the placement lock")
	ErrMutationUnverified   = errors.New("residency: mutation could not be verified")
)

var sha256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// PlacementLockStore is the authoritative durable store. Implementations must
// return the resolved Region set captured when the lock was created.
type PlacementLockStore interface {
	LoadPlacementLock(context.Context, string) (*placement.PlacementLock, error)
}

// ObjectIdentity is provider metadata observed independently after a write.
type ObjectIdentity struct {
	Digest  string
	Size    int64
	ETag    string
	Version string
}

// MutationInspector performs the provider-backed read-after-write check.
type MutationInspector interface {
	HeadMutation(context.Context, placement.RegionCode, string, string) (ObjectIdentity, bool, error)
}

// MutationReceipt names the durable object created by one typed operation.
// The coordinator does not accept the receipt until MutationInspector returns
// the same immutable identity from the requested Region.
type MutationReceipt struct {
	DatabaseID          string
	Region              placement.RegionCode
	PlacementGeneration uint64
	Bucket              string
	ObjectKey           string
	Digest              string
	Size                int64
	ETag                string
	Version             string
}

type BootstrapRequest struct {
	DatabaseID          string
	TargetRegion        placement.RegionCode
	PlacementGeneration uint64
}

type RepairRequest struct {
	DatabaseID          string
	SourceRegion        placement.RegionCode
	TargetRegion        placement.RegionCode
	PlacementGeneration uint64
}

type BackupRequest struct {
	DatabaseID          string
	SourceRegion        placement.RegionCode
	TargetRegion        placement.RegionCode
	PlacementGeneration uint64
}

type RestoreRequest struct {
	DatabaseID          string
	BackupRegion        placement.RegionCode
	TargetRegion        placement.RegionCode
	PlacementGeneration uint64
}

type ExportRequest struct {
	DatabaseID          string
	SourceRegion        placement.RegionCode
	TargetRegion        placement.RegionCode
	PlacementGeneration uint64
}

type BranchRequest struct {
	DatabaseID          string
	SourceRegion        placement.RegionCode
	TargetRegion        placement.RegionCode
	PlacementGeneration uint64
}

type RegionChangeRequest struct {
	DatabaseID          string
	SourceRegion        placement.RegionCode
	TargetRegion        placement.RegionCode
	PlacementGeneration uint64
	UpdatedLock         *placement.PlacementLock
}

type BootstrapPort interface {
	Bootstrap(context.Context, BootstrapRequest) (MutationReceipt, error)
}

type RepairPort interface {
	Repair(context.Context, RepairRequest) (MutationReceipt, error)
}

type BackupPort interface {
	Backup(context.Context, BackupRequest) (MutationReceipt, error)
}

type RestorePort interface {
	Restore(context.Context, RestoreRequest) (MutationReceipt, error)
}

type ExportPort interface {
	Export(context.Context, ExportRequest) (MutationReceipt, error)
}

type BranchPort interface {
	Branch(context.Context, BranchRequest) (MutationReceipt, error)
}

type RegionChangePort interface {
	ChangeRegion(context.Context, RegionChangeRequest) (MutationReceipt, error)
}

// Ports are the concrete mutation boundaries. They are separate on purpose:
// production composition cannot turn a generic operation-name callback into
// proof for seven unrelated storage actions.
type Ports struct {
	Bootstrap    BootstrapPort
	Repair       RepairPort
	Backup       BackupPort
	Restore      RestorePort
	Export       ExportPort
	Branch       BranchPort
	RegionChange RegionChangePort
}

// Coordinator is the production residency gate for storage mutations.
type Coordinator struct {
	locks     PlacementLockStore
	inspector MutationInspector
	ports     Ports
}

func NewCoordinator(locks PlacementLockStore, inspector MutationInspector, ports Ports) (*Coordinator, error) {
	if interfaceNil(locks) || interfaceNil(inspector) || interfaceNil(ports.Bootstrap) ||
		interfaceNil(ports.Repair) || interfaceNil(ports.Backup) || interfaceNil(ports.Restore) ||
		interfaceNil(ports.Export) || interfaceNil(ports.Branch) || interfaceNil(ports.RegionChange) {
		return nil, ErrProductionDependency
	}
	return &Coordinator{locks: locks, inspector: inspector, ports: ports}, nil
}

func (c *Coordinator) Bootstrap(ctx context.Context, request BootstrapRequest) (MutationReceipt, error) {
	if _, err := c.authorize(ctx, request.DatabaseID, request.PlacementGeneration, request.TargetRegion); err != nil {
		return MutationReceipt{}, err
	}
	receipt, err := c.ports.Bootstrap.Bootstrap(ctx, request)
	return c.finish(ctx, request.DatabaseID, request.TargetRegion, request.PlacementGeneration, receipt, err)
}

func (c *Coordinator) Repair(ctx context.Context, request RepairRequest) (MutationReceipt, error) {
	if _, err := c.authorize(ctx, request.DatabaseID, request.PlacementGeneration, request.SourceRegion, request.TargetRegion); err != nil {
		return MutationReceipt{}, err
	}
	receipt, err := c.ports.Repair.Repair(ctx, request)
	return c.finish(ctx, request.DatabaseID, request.TargetRegion, request.PlacementGeneration, receipt, err)
}

func (c *Coordinator) Backup(ctx context.Context, request BackupRequest) (MutationReceipt, error) {
	if _, err := c.authorize(ctx, request.DatabaseID, request.PlacementGeneration, request.SourceRegion, request.TargetRegion); err != nil {
		return MutationReceipt{}, err
	}
	receipt, err := c.ports.Backup.Backup(ctx, request)
	return c.finish(ctx, request.DatabaseID, request.TargetRegion, request.PlacementGeneration, receipt, err)
}

func (c *Coordinator) Restore(ctx context.Context, request RestoreRequest) (MutationReceipt, error) {
	if _, err := c.authorize(ctx, request.DatabaseID, request.PlacementGeneration, request.BackupRegion, request.TargetRegion); err != nil {
		return MutationReceipt{}, err
	}
	receipt, err := c.ports.Restore.Restore(ctx, request)
	return c.finish(ctx, request.DatabaseID, request.TargetRegion, request.PlacementGeneration, receipt, err)
}

func (c *Coordinator) Export(ctx context.Context, request ExportRequest) (MutationReceipt, error) {
	if _, err := c.authorize(ctx, request.DatabaseID, request.PlacementGeneration, request.SourceRegion, request.TargetRegion); err != nil {
		return MutationReceipt{}, err
	}
	receipt, err := c.ports.Export.Export(ctx, request)
	return c.finish(ctx, request.DatabaseID, request.TargetRegion, request.PlacementGeneration, receipt, err)
}

func (c *Coordinator) Branch(ctx context.Context, request BranchRequest) (MutationReceipt, error) {
	if _, err := c.authorize(ctx, request.DatabaseID, request.PlacementGeneration, request.SourceRegion, request.TargetRegion); err != nil {
		return MutationReceipt{}, err
	}
	receipt, err := c.ports.Branch.Branch(ctx, request)
	return c.finish(ctx, request.DatabaseID, request.TargetRegion, request.PlacementGeneration, receipt, err)
}

func (c *Coordinator) ChangeRegion(ctx context.Context, request RegionChangeRequest) (MutationReceipt, error) {
	lock, err := c.authorize(ctx, request.DatabaseID, request.PlacementGeneration, request.SourceRegion, request.TargetRegion)
	if err != nil {
		return MutationReceipt{}, err
	}
	if request.UpdatedLock == nil || placement.CheckPlacementLockWidening(lock, request.UpdatedLock) != nil || !sameLock(lock, request.UpdatedLock) {
		return MutationReceipt{}, ErrLockMismatch
	}
	receipt, err := c.ports.RegionChange.ChangeRegion(ctx, request)
	return c.finish(ctx, request.DatabaseID, request.TargetRegion, request.PlacementGeneration, receipt, err)
}

func (c *Coordinator) authorize(ctx context.Context, database string, generation uint64, regions ...placement.RegionCode) (*placement.PlacementLock, error) {
	if c == nil || interfaceNil(c.locks) || interfaceNil(c.inspector) {
		return nil, ErrProductionDependency
	}
	if ctx == nil || !validDatabaseID(database) || generation == 0 || len(regions) == 0 {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, region := range regions {
		if !region.IsValid() {
			return nil, ErrInvalidRequest
		}
	}
	lock, err := c.locks.LoadPlacementLock(ctx, database)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLockUnavailable, err)
	}
	if lock == nil || lock.Generation != generation || lock.PlacementGeneration != generation || len(lock.Regions) == 0 {
		return nil, ErrLockMismatch
	}
	validated, err := placement.NewPlacementLock(lock.Kind, lock.Regions, lock.Generation)
	if err != nil || !sameLock(lock, validated) {
		return nil, ErrLockMismatch
	}
	for _, region := range regions {
		if !containsRegion(lock.Regions, region) {
			return nil, fmt.Errorf("%w: %s", ErrRegionOutsideLock, region.Value())
		}
	}
	return copyLock(lock), nil
}

func (c *Coordinator) finish(ctx context.Context, database string, region placement.RegionCode, generation uint64, receipt MutationReceipt, mutationErr error) (MutationReceipt, error) {
	if mutationErr != nil {
		return MutationReceipt{}, mutationErr
	}
	if receipt.DatabaseID != database || receipt.Region != region || receipt.PlacementGeneration != generation ||
		!validObjectPart(receipt.Bucket) || !validObjectKey(receipt.ObjectKey) || receipt.Size <= 0 ||
		!sha256DigestPattern.MatchString(receipt.Digest) || strings.TrimSpace(receipt.ETag) == "" {
		return MutationReceipt{}, ErrMutationUnverified
	}
	identity, found, err := c.inspector.HeadMutation(ctx, region, receipt.Bucket, receipt.ObjectKey)
	if err != nil {
		return MutationReceipt{}, fmt.Errorf("%w: %v", ErrMutationUnverified, err)
	}
	if !found || identity.Size != receipt.Size || !strings.EqualFold(identity.Digest, receipt.Digest) ||
		identity.ETag == "" || identity.ETag != receipt.ETag ||
		(receipt.Version != "" && identity.Version != receipt.Version) {
		return MutationReceipt{}, ErrMutationUnverified
	}
	return receipt, nil
}

func validDatabaseID(value string) bool {
	return value != "" && len(value) <= 255 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "/\\\x00\r\n")
}

func validObjectPart(value string) bool {
	return value != "" && len(value) <= 255 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "/\\\x00\r\n")
}

func validObjectKey(value string) bool {
	return value != "" && len(value) <= 1024 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\\\x00\r\n") && !strings.HasPrefix(value, "/")
}

func containsRegion(regions []placement.RegionCode, want placement.RegionCode) bool {
	for _, region := range regions {
		if region == want {
			return true
		}
	}
	return false
}

func sameLock(left, right *placement.PlacementLock) bool {
	if left == nil || right == nil || left.Kind != right.Kind || left.Generation != right.Generation ||
		left.PlacementGeneration != right.PlacementGeneration || len(left.Regions) != len(right.Regions) {
		return false
	}
	for _, region := range left.Regions {
		if !containsRegion(right.Regions, region) {
			return false
		}
	}
	return true
}

func copyLock(lock *placement.PlacementLock) *placement.PlacementLock {
	if lock == nil {
		return nil
	}
	copyValue := *lock
	copyValue.Regions = append([]placement.RegionCode(nil), lock.Regions...)
	return &copyValue
}

func interfaceNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
