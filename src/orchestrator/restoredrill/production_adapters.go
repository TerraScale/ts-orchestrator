package restoredrill

// This file is the production boundary for the restore drill.  The drill
// package owns the sequencing and durable state machine; these adapters own
// the admission checks which keep a test-only or process-local implementation
// from being accidentally used by the production composition.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

var (
	ErrProductionDependency    = errors.New("restore drill: production dependency is unavailable")
	ErrSnapshotVerification    = errors.New("restore drill: snapshot durability verification is unavailable")
	ErrArtifactVerification    = errors.New("restore drill: release artifact mirror verification is unavailable")
	ErrInvalidRestoreRequest   = errors.New("restore drill: invalid restore request")
	ErrInvalidScratchRequest   = errors.New("restore drill: invalid scratch request")
	ErrInvalidSnapshotIdentity = errors.New("restore drill: invalid snapshot identity")
	ErrInvalidSnapshotRegion   = errors.New("restore drill: invalid snapshot Region")
)

// ProductionBackupAdapter guards the TerraBase native-backup boundary.  The
// underlying client is deliberately a port: this package must not carry
// customer data or know the TerraBase protocol.
type ProductionBackupAdapter struct{ Port BackupPort }

func NewProductionBackupAdapter(port BackupPort) (*ProductionBackupAdapter, error) {
	if isNil(port) {
		return nil, fmt.Errorf("%w: backup port", ErrProductionDependency)
	}
	return &ProductionBackupAdapter{Port: port}, nil
}

func (a *ProductionBackupAdapter) ListDatabases(ctx context.Context) ([]Database, error) {
	if a == nil || a.Port == nil {
		return nil, fmt.Errorf("%w: backup port", ErrProductionDependency)
	}
	if ctx == nil {
		return nil, errors.New("restore drill: backup context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	databases, err := a.Port.ListDatabases(ctx)
	if err != nil {
		return nil, sanitizeError(err)
	}
	for _, database := range databases {
		if !validID(database.ID) {
			return nil, fmt.Errorf("%w: database identity", ErrInvalidRestoreRequest)
		}
	}
	return databases, nil
}

func (a *ProductionBackupAdapter) Restore(ctx context.Context, request RestoreRequest) error {
	if a == nil || a.Port == nil {
		return fmt.Errorf("%w: backup port", ErrProductionDependency)
	}
	if ctx == nil {
		return errors.New("restore drill: backup context is required")
	}
	if err := validateRestoreRequest(request); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return sanitizeError(a.Port.Restore(ctx, request))
}

func validateRestoreRequest(request RestoreRequest) error {
	if !validID(request.SourceDatabaseID) ||
		strings.TrimSpace(request.BranchID) == "" ||
		strings.TrimSpace(request.JournalCut) == "" ||
		request.RestoreEpoch == 0 || !validToken(request.IdempotencyKey) || strings.ContainsAny(request.BranchID+request.JournalCut, "\x00\r\n") {
		return ErrInvalidRestoreRequest
	}
	return nil
}

func validID(value string) bool {
	if value == "" || len(value) > 255 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n/\\") {
		return false
	}
	return true
}

func validToken(value string) bool {
	return value != "" && len(value) <= 512 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

// ProductionBranchAdapter guards scratch-branch ownership and cleanup.  A
// branch ID is an ownership receipt; an empty ID is never accepted and a
// delete always receives a non-empty ID.
type ProductionBranchAdapter struct{ Port BranchPort }

func NewProductionBranchAdapter(port BranchPort) (*ProductionBranchAdapter, error) {
	if isNil(port) {
		return nil, fmt.Errorf("%w: branch port", ErrProductionDependency)
	}
	return &ProductionBranchAdapter{Port: port}, nil
}

func (a *ProductionBranchAdapter) CreateScratch(ctx context.Context, request ScratchBranchRequest) (ScratchBranch, error) {
	if a == nil || a.Port == nil {
		return ScratchBranch{}, fmt.Errorf("%w: branch port", ErrProductionDependency)
	}
	if ctx == nil {
		return ScratchBranch{}, errors.New("restore drill: branch context is required")
	}
	if !validID(request.SourceDatabaseID) || !validToken(request.Name) ||
		!validToken(request.IdempotencyKey) || request.RestoreEpoch == 0 {
		return ScratchBranch{}, ErrInvalidScratchRequest
	}
	if err := ctx.Err(); err != nil {
		return ScratchBranch{}, err
	}
	branch, err := a.Port.CreateScratch(ctx, request)
	if err != nil {
		return branch, sanitizeError(err)
	}
	if !validID(branch.ID) {
		return ScratchBranch{}, fmt.Errorf("%w: provider returned no branch ID", ErrInvalidScratchRequest)
	}
	return branch, nil
}

func (a *ProductionBranchAdapter) Stats(ctx context.Context, branch ScratchBranch) (RestoreStats, error) {
	if a == nil || a.Port == nil {
		return RestoreStats{}, fmt.Errorf("%w: branch port", ErrProductionDependency)
	}
	if ctx == nil {
		return RestoreStats{}, errors.New("restore drill: branch context is required")
	}
	if !validID(branch.ID) {
		return RestoreStats{}, ErrInvalidScratchRequest
	}
	if err := ctx.Err(); err != nil {
		return RestoreStats{}, err
	}
	stats, err := a.Port.Stats(ctx, branch)
	if err != nil {
		return stats, sanitizeError(err)
	}
	if strings.TrimSpace(stats.Checksum) == "" || stats.RowCount < 0 {
		return RestoreStats{}, fmt.Errorf("%w: provider returned invalid restore facts", ErrInvalidScratchRequest)
	}
	return stats, nil
}

func (a *ProductionBranchAdapter) Delete(ctx context.Context, branch ScratchBranch) error {
	if a == nil || a.Port == nil {
		return fmt.Errorf("%w: branch port", ErrProductionDependency)
	}
	if ctx == nil {
		return errors.New("restore drill: branch cleanup context is required")
	}
	if !validID(branch.ID) {
		return ErrInvalidScratchRequest
	}
	return sanitizeError(a.Port.Delete(ctx, branch))
}

// VerifiedSnapshotMirror is the additional provider contract required by
// production.  Mirror alone is insufficient: an in-memory object echo can
// claim success without proving that bytes reached each Region's durable
// Object Storage bucket. VerifyMirror must perform a provider-backed HEAD (or
// equivalent) and compare the immutable snapshot identity.
type VerifiedSnapshotMirror interface {
	JetStreamSnapshotMirror
	VerifyMirror(context.Context, ControlStateSnapshot, string) error
}

// ProductionSnapshotAdapter validates the identity returned by the
// JetStream snapshot provider before it can enter the durable run record.
// This keeps a provider that accidentally returns a different object or
// control epoch from being treated as evidence for today's run.
type ProductionSnapshotAdapter struct{ Port JetStreamSnapshotter }

func NewProductionSnapshotAdapter(port JetStreamSnapshotter) (*ProductionSnapshotAdapter, error) {
	if isNil(port) {
		return nil, fmt.Errorf("%w: JetStream snapshotter", ErrProductionDependency)
	}
	return &ProductionSnapshotAdapter{Port: port}, nil
}

func (a *ProductionSnapshotAdapter) Snapshot(ctx context.Context, request SnapshotRequest) (ControlStateSnapshot, error) {
	if a == nil || a.Port == nil {
		return ControlStateSnapshot{}, fmt.Errorf("%w: JetStream snapshotter", ErrProductionDependency)
	}
	if ctx == nil {
		return ControlStateSnapshot{}, errors.New("restore drill: snapshot context is required")
	}
	if !validToken(request.RunID) || !validToken(request.ObjectKey) ||
		!validToken(request.IdempotencyKey) || request.ControlEpoch == 0 || strings.ContainsAny(request.ObjectKey, "\x00\r\n") {
		return ControlStateSnapshot{}, ErrInvalidSnapshotIdentity
	}
	if err := ctx.Err(); err != nil {
		return ControlStateSnapshot{}, err
	}
	snapshot, err := a.Port.Snapshot(ctx, request)
	if err != nil {
		return snapshot, sanitizeError(err)
	}
	if err := validateSnapshotIdentity(snapshot); err != nil {
		return snapshot, err
	}
	if snapshot.ObjectKey != request.ObjectKey ||
		snapshot.ControlEpoch != request.ControlEpoch {
		return snapshot, ErrRestoreEpochFenced
	}
	return snapshot, nil
}

// ProductionSnapshotMirrorAdapter turns the verified provider contract into
// the existing JetStreamSnapshotMirror port consumed by Drill.
type ProductionSnapshotMirrorAdapter struct{ Port VerifiedSnapshotMirror }

func NewProductionSnapshotMirrorAdapter(port JetStreamSnapshotMirror) (*ProductionSnapshotMirrorAdapter, error) {
	verified, ok := port.(VerifiedSnapshotMirror)
	if !ok || isNil(verified) {
		return nil, fmt.Errorf("%w: JetStream mirror must implement VerifyMirror", ErrSnapshotVerification)
	}
	return &ProductionSnapshotMirrorAdapter{Port: verified}, nil
}

func (a *ProductionSnapshotMirrorAdapter) Mirror(ctx context.Context, snapshot ControlStateSnapshot, region string) error {
	if a == nil || a.Port == nil {
		return fmt.Errorf("%w: snapshot mirror", ErrProductionDependency)
	}
	if ctx == nil {
		return errors.New("restore drill: snapshot context is required")
	}
	if err := validateSnapshotIdentity(snapshot); err != nil {
		return err
	}
	if strings.TrimSpace(region) == "" {
		return ErrInvalidSnapshotRegion
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.Port.Mirror(ctx, snapshot, region); err != nil {
		return sanitizeError(err)
	}
	// Verify after every write, including an idempotent retry. This closes the
	// gap where a provider reports an existing object but the object changed.
	return sanitizeError(a.Port.VerifyMirror(ctx, snapshot, region))
}

func validateSnapshotIdentity(snapshot ControlStateSnapshot) error {
	if strings.TrimSpace(snapshot.ID) == "" || strings.TrimSpace(snapshot.ObjectKey) == "" ||
		strings.TrimSpace(snapshot.Checksum) == "" || snapshot.Size < 0 ||
		snapshot.ControlEpoch == 0 {
		return ErrInvalidSnapshotIdentity
	}
	return nil
}

// ProductionArtifactMirrorAdapter is deliberately backed by delivery's
// existing all-Region mirror. Its constructor requires the optional HEAD
// contract, because a Put-only or local in-memory store cannot prove that an
// immutable release artifact is present in every Region.
type ProductionArtifactMirrorAdapter struct{ Mirror *delivery.ArtifactMirror }

func NewProductionArtifactMirrorAdapter(mirror *delivery.ArtifactMirror) (*ProductionArtifactMirrorAdapter, error) {
	if mirror == nil || isNil(mirror.Store) {
		return nil, fmt.Errorf("%w: release artifact mirror", ErrProductionDependency)
	}
	if _, ok := mirror.Store.(delivery.RegionObjectStoreInspector); !ok {
		return nil, fmt.Errorf("%w: release artifact store must support read-after-write inspection", ErrArtifactVerification)
	}
	if len(mirror.Spec.Regions) == 0 {
		return nil, fmt.Errorf("%w: release artifact mirror has no Regions", ErrArtifactVerification)
	}
	return &ProductionArtifactMirrorAdapter{Mirror: mirror}, nil
}

func (a *ProductionArtifactMirrorAdapter) MirrorAll(ctx context.Context, artifact *delivery.ReleaseArtifact) error {
	if a == nil || a.Mirror == nil {
		return fmt.Errorf("%w: release artifact mirror", ErrProductionDependency)
	}
	if ctx == nil {
		return errors.New("restore drill: artifact mirror context is required")
	}
	if artifact == nil {
		return fmt.Errorf("%w: release artifact is nil", ErrArtifactVerification)
	}
	return sanitizeError(a.Mirror.MirrorAll(ctx, artifact))
}

// ProductionConfig is the single composition input for the D-71 runtime.
// Every port is an authoritative service boundary. In particular, this type
// has no local filesystem/object-store fallback.
type ProductionConfig struct {
	Backup    BackupPort
	Branches  BranchPort
	Journal   JournalPort
	Scheduler SchedulerPort
	Pager     PagerPort

	Drill Config

	Snapshotter     JetStreamSnapshotter
	SnapshotMirror  JetStreamSnapshotMirror
	SnapshotRegions []string

	ArtifactMirror *delivery.ArtifactMirror
}

// ProductionComposition is returned to the command composition root. The
// drill is ready to Run/Start, while ArtifactMirror is the pre-rollout hook
// used by delivery before any host activation begins.
type ProductionComposition struct {
	Drill          *Drill
	ArtifactMirror *ProductionArtifactMirrorAdapter
}

// NewProductionComposition is the one integration function for parent wiring.
// It admits only a complete D-71 path: backup restore, scratch cleanup,
// durable journal, daily scheduling, failure paging, verified JetStream
// snapshots in every Region, and read-after-write release mirrors.
func NewProductionComposition(config ProductionConfig) (*ProductionComposition, error) {
	backup, err := NewProductionBackupAdapter(config.Backup)
	if err != nil {
		return nil, err
	}
	branches, err := NewProductionBranchAdapter(config.Branches)
	if err != nil {
		return nil, err
	}
	if isNil(config.Journal) || isNil(config.Scheduler) || isNil(config.Pager) {
		return nil, fmt.Errorf("%w: journal, scheduler, and pager are required", ErrProductionDependency)
	}
	if isNil(config.Snapshotter) || isNil(config.SnapshotMirror) || len(config.SnapshotRegions) == 0 {
		return nil, fmt.Errorf("%w: daily JetStream snapshot and all-Region mirror are required", ErrSnapshotVerification)
	}
	snapshotter, err := NewProductionSnapshotAdapter(config.Snapshotter)
	if err != nil {
		return nil, err
	}
	mirror, err := NewProductionSnapshotMirrorAdapter(config.SnapshotMirror)
	if err != nil {
		return nil, err
	}
	artifactMirror, err := NewProductionArtifactMirrorAdapter(config.ArtifactMirror)
	if err != nil {
		return nil, err
	}

	drillConfig := config.Drill
	drillConfig.Snapshotter = snapshotter
	drillConfig.SnapshotMirror = mirror
	drillConfig.SnapshotRegions = append([]string(nil), config.SnapshotRegions...)
	drill, err := New(backup, branches, config.Journal, config.Scheduler, config.Pager, drillConfig)
	if err != nil {
		return nil, err
	}
	return &ProductionComposition{Drill: drill, ArtifactMirror: artifactMirror}, nil
}
