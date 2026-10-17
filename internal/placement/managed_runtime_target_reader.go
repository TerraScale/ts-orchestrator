package placement

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// ManagedRuntimeTargetReader observes exact placement and canary records under
// a genuine current lease. It cannot grant artifact admission or material access.
type ManagedRuntimeTargetReader struct {
	original context.Context
	config   Config
	reader   *authority.Reader
	lease    *authority.LeaseAdmission
	members  MemberPinReader
	deadline time.Time
}

func NewManagedRuntimeTargetReader(ctx context.Context, config Config, reader *authority.Reader,
	lease *authority.LeaseAdmission, members MemberPinReader,
) (*ManagedRuntimeTargetReader, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil || lease == nil || members == nil {
		return nil, errors.New("managed runtime reader requires actual authority, lease and member sources")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Done() == nil || !time.Now().Before(deadline) || lease.Guard(ctx) != nil {
		return nil, authority.ErrFenced
	}
	config.FaultDomains = slices.Clone(config.FaultDomains)
	return &ManagedRuntimeTargetReader{original: ctx, config: config, reader: reader, lease: lease, members: members,
		deadline: earlierManagedRuntimeDeadline(deadline, lease.Deadline())}, nil
}

type managedRuntimeTargetSnapshot struct {
	placement authority.LogEntry
	member    VersionedMemberState
	history   []authority.LogEntry
	latest    authority.LogEntry
	artifact  AdmittedArtifact
}

// ManagedRuntimeTargetAdmission retains original observed source revisions.
// ArtifactPins are descriptive: root must independently resolve the actual signed
// artifact and recheck Guard after that awaited resolution before ciphertext.
type ManagedRuntimeTargetAdmission struct {
	reader       *ManagedRuntimeTargetReader
	original     context.Context
	deadline     time.Time
	desired      host.Desired
	registration host.Registration
	snapshot     managedRuntimeTargetSnapshot
}

func (a *ManagedRuntimeTargetAdmission) ArtifactPins() AdmittedArtifact { return a.snapshot.artifact }

func (r *ManagedRuntimeTargetReader) Admit(ctx context.Context, desired host.Desired, registration host.Registration) (*ManagedRuntimeTargetAdmission, bool, error) {
	if err := r.guard(ctx); err != nil {
		return nil, false, err
	}
	if desired.AuthorityEpoch != r.lease.Epoch() {
		return nil, false, authority.ErrFenced
	}
	original := ctx
	ctx, cancel, err := managedRuntimeContext(r.original, original, r.deadline)
	if err != nil {
		return nil, false, err
	}
	defer cancel()
	snapshot, updated, err := r.read(ctx, desired, registration)
	if err != nil || !updated {
		return nil, false, err
	}
	deadline, _ := ctx.Deadline()
	admitted := &ManagedRuntimeTargetAdmission{reader: r, original: original, deadline: deadline, snapshot: snapshot}
	desiredWire, err := protocol.EncodeJSON(desired)
	if err != nil {
		return nil, false, err
	}
	registrationWire, err := protocol.EncodeJSON(registration)
	if err != nil {
		return nil, false, err
	}
	if err := protocol.DecodeStrict(desiredWire, &admitted.desired, 64<<10); err != nil {
		return nil, false, err
	}
	if err := protocol.DecodeStrict(registrationWire, &admitted.registration, 64<<10); err != nil {
		return nil, false, err
	}
	if err := admitted.Guard(ctx); err != nil {
		return nil, false, err
	}
	return admitted, true, nil
}

func (r *ManagedRuntimeTargetReader) guard(ctx context.Context) error {
	if r == nil {
		return authority.ErrFenced
	}
	readCtx, cancel, err := managedRuntimeContext(r.original, ctx, r.deadline)
	if err != nil {
		return err
	}
	defer cancel()
	if err := r.lease.Guard(readCtx); err != nil {
		return err
	}
	if r.original.Err() != nil || ctx.Err() != nil || !time.Now().Before(r.deadline) {
		return authority.ErrFenced
	}
	return readCtx.Err()
}

func (a *ManagedRuntimeTargetAdmission) Guard(ctx context.Context) error {
	if a == nil || a.reader == nil {
		return authority.ErrFenced
	}
	r := a.reader
	caller := ctx
	sourceCtx, stopOriginal, err := managedRuntimeContext(r.original, a.original, a.deadline)
	if err != nil {
		return err
	}
	defer stopOriginal()
	ctx, stopCaller, err := managedRuntimeContext(sourceCtx, caller, a.deadline)
	if err != nil {
		return err
	}
	defer stopCaller()
	deadline, _ := ctx.Deadline()
	if err := r.guard(ctx); err != nil {
		return err
	}
	current, updated, err := r.read(ctx, a.desired, a.registration)
	if err != nil {
		return err
	}
	if !updated || !reflect.DeepEqual(a.snapshot, current) {
		return errors.New("original managed runtime target or source revision changed")
	}
	if err := r.guard(ctx); err != nil {
		return err
	}
	if a.original.Err() != nil || caller.Err() != nil || !time.Now().Before(a.deadline) || !time.Now().Before(deadline) {
		return authority.ErrFenced
	}
	return ctx.Err()
}

// Preserve the original authority-bound values; later callers only narrow its
// lifetime and cannot replace the retained source context.
func managedRuntimeContext(original, caller context.Context, deadline time.Time) (context.Context, context.CancelFunc, error) {
	if original == nil || caller == nil || original.Err() != nil || caller.Err() != nil || !time.Now().Before(deadline) {
		return nil, nil, authority.ErrFenced
	}
	if callerDeadline, ok := caller.Deadline(); ok {
		deadline = earlierManagedRuntimeDeadline(deadline, callerDeadline)
	}
	ctx, cancel := context.WithDeadline(original, deadline)
	stop := context.AfterFunc(caller, cancel)
	return ctx, func() { stop(); cancel() }, nil
}

func (r *ManagedRuntimeTargetReader) read(ctx context.Context, desired host.Desired, registration host.Registration) (managedRuntimeTargetSnapshot, bool, error) {
	snapshot, updated, err := readManagedRuntimeTarget(ctx, r.config, r.members, r.reader, r.reader, r.reader,
		r.lease.Epoch(), desired, registration)
	if err != nil || !updated {
		return managedRuntimeTargetSnapshot{}, false, err
	}
	entry := snapshot.placement
	binding := registration.ManagedPlacement
	if entry.Kind != authority.MutationPlacementIntent || entry.Sequence == 0 || entry.Epoch == 0 ||
		entry.SubjectKey != binding.DatabaseID+"."+binding.PartitionID {
		return managedRuntimeTargetSnapshot{}, false, errors.New("managed runtime placement entry is malformed")
	}
	state := snapshot.member.State
	snapshot.history, err = r.reader.ReadManagedUpdateOperation(ctx, state.DatabaseID, state.PartitionID, state.ManagedRuntimeTarget.OperationID)
	if err != nil {
		return managedRuntimeTargetSnapshot{}, false, err
	}
	snapshot.latest, err = r.reader.ReadManagedUpdate(ctx, state.DatabaseID, state.PartitionID)
	if err != nil {
		return managedRuntimeTargetSnapshot{}, false, err
	}
	return snapshot, true, nil
}

func earlierManagedRuntimeDeadline(left, right time.Time) time.Time {
	if right.Before(left) {
		return right
	}
	return left
}

func managedLocalSeats(config Config, intent Intent) ([]Seat, error) {
	if !slices.Contains(intent.ActiveRegions, config.Region) {
		return nil, nil
	}
	return RegionSeats(config.Region, config.FaultDomains, SeatsPerRegion)
}

func managedSeatForMember(config Config, intent Intent, region oci.Region, memberID string) (Seat, bool) {
	seats, err := managedLocalSeats(config, intent)
	if err != nil {
		return Seat{}, false
	}
	for _, seat := range seats {
		if seat.Region == region && seat.MemberID == memberID {
			return seat, true
		}
	}
	return Seat{}, false
}

func managedMemberDesired(config Config, epoch uint64, intent Intent, state MemberState, seat Seat) (host.Desired, error) {
	manifest := state.EffectiveRuntimeManifest()
	roster, row := intent.CanonicalRoster, state.CanonicalRosterRow
	binding := host.ManagedMemberBinding{Scope: host.MemberScope{
		ClusterID: roster.ClusterID, TenantID: roster.TenantID, DatabaseID: roster.DatabaseID,
		ShardID: roster.ShardID, MemberID: row.MemberID, Incarnation: row.Incarnation,
	}, HostAttempt: state.HostAttempt}
	mountPath, err := host.ManagedMountPath(manifest.ManagedRuntimeRoot, binding)
	if err != nil {
		return host.Desired{}, err
	}
	return host.Desired{
		Cell: config.Cell, Node: state.HostNode, Environment: config.Environment,
		Role: config.MemberRole, Digest: manifest.ArtifactDigest,
		Generation: state.DesiredGeneration, AuthorityEpoch: epoch,
		ManagedMember: &host.ManagedMemberLaunch{
			OCI: host.ManagedOCIBinding{
				Region: string(seat.Region), InstanceID: state.InstanceID, Owner: config.ManagedOwner,
				FleetGeneration: config.FleetGeneration, CreateKey: state.CreateKey,
			},
			Member: binding,
			Authority: host.MemberAuthority{
				Epoch: state.AuthorityReference.Epoch, ConfigurationID: state.AuthorityReference.ConfigurationID,
				CertificateSHA256: state.AuthorityReference.CertificateSHA256,
				TLSLeafSHA256:     state.CanonicalRosterRow.TLSLeafSHA256,
			},
			SourceDigest: manifest.SourceDigest, VolumeID: state.VolumeID,
			AttachmentID: state.AttachmentID, AttachmentETag: state.AttachmentETag,
			ProcessMemoryBytes:   state.ManagedHostProfile.ProcessMemoryBytes,
			MemoryHeadroomBytes:  state.ManagedHostProfile.MemoryHeadroomBytes,
			CgroupMemoryMaxBytes: state.ManagedHostProfile.CgroupMemoryMaxBytes,
			SystemReserveBytes:   state.ManagedHostProfile.SystemReserveBytes,
			Runtime: &host.ManagedRuntimePins{
				DevicePath: state.AttachmentDevice, MountPath: mountPath,
				FileSystemUUID: manifest.FileSystemUUID, FileSystemType: manifest.FileSystemType,
				TrustedKeySHA256:                    manifest.TrustedKeySHA256,
				ServerCertificateSHA256:             manifest.ServerCertificateSHA256,
				ServerPrivateKeySHA256:              manifest.ServerPrivateKeySHA256,
				ClientCARootsSHA256:                 manifest.ClientCARootsSHA256,
				ClientManagedMaterialManifestSHA256: manifest.ClientManagedMaterialManifestSHA256,
				SQLSchemaBundleSHA256:               manifest.SQLSchemaBundleSHA256,
				LiveS3ConfigSHA256:                  manifest.LiveS3ConfigSHA256,
				LiveS3TargetSHA256:                  manifest.LiveS3TargetSHA256,
				LiveS3Credential:                    manifest.LiveS3Credential,
				BackupManifestSHA256:                manifest.BackupManifestSHA256,
				BackupS3ConfigSHA256:                manifest.BackupS3ConfigSHA256,
				BackupS3TargetSHA256:                manifest.BackupS3TargetSHA256,
				BackupS3CredentialSHA256:            manifest.BackupS3CredentialSHA256,
				BackupDataKeySHA256:                 manifest.BackupDataKeySHA256,
				BackupOwner:                         manifest.BackupOwner,
				BackupS3Credential:                  manifest.BackupS3Credential,
				BackupDataKey:                       manifest.BackupDataKey,
				ReplicationListenAddress:            manifest.ReplicationListenAddress,
				ReplicationPeerMemberID:             manifest.ReplicationPeerMemberID,
				ReplicationPeerAddress:              manifest.ReplicationPeerAddress,
				ReplicationServerCASHA256:           manifest.ReplicationServerCASHA256,
			},
		},
	}, nil
}

func managedUpdatePrepareIsCurrent(ctx context.Context, cell string, reader authority.ManagedUpdateReader, placementReader managedUpdatePlacementReader, state MemberState) (bool, error) {
	target := state.ManagedRuntimeTarget
	entries, err := reader.ReadManagedUpdateOperation(ctx, state.DatabaseID, state.PartitionID, target.OperationID)
	if err != nil {
		if errors.Is(err, authority.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if len(entries) == 0 {
		return false, nil
	}
	var preparedEntry authority.LogEntry
	for _, entry := range entries {
		if managedUpdatePhaseFromSubject(entry.SubjectKey) == authority.ManagedUpdatePrepared {
			preparedEntry = entry
			break
		}
	}
	if preparedEntry.Kind != authority.MutationManagedUpdate || preparedEntry.Sequence != target.AuthoritySequence ||
		preparedEntry.OperationID != target.OperationID {
		return false, nil
	}
	record, intent, envelope, err := decodeManagedUpdateRequest(preparedEntry, cell)
	if err != nil {
		return false, err
	}
	if record.PlacementGeneration != target.PlacementGeneration ||
		record.PlacementPayloadDigest != target.PlacementPayloadDigest ||
		record.CanarySeatID != target.CanarySeatID ||
		record.CanaryDesiredGeneration != target.DesiredGeneration ||
		record.CandidateArtifactDigest != target.ArtifactDigest ||
		record.CandidateManifestDigest != target.ManifestDigest ||
		record.CandidateSourceDigest != target.SourceDigest ||
		record.SignedRequestSHA256 != target.RequestSHA256 ||
		intent.DatabaseID != state.DatabaseID || intent.PartitionID != state.PartitionID ||
		intent.CanarySeatID != state.MemberID || envelope.Epoch != preparedEntry.Epoch {
		return false, nil
	}
	latest, err := reader.ReadManagedUpdate(ctx, state.DatabaseID, state.PartitionID)
	if err != nil {
		return false, err
	}
	if latest.Kind != authority.MutationManagedUpdate {
		return false, nil
	}
	if latest.OperationID != preparedEntry.OperationID || latest.Sequence != preparedEntry.Sequence {
		// The operation is no longer the latest prepared request, so it stays
		// current only through its own retained canary-serving outcome. Once a
		// later operation follows, the seat must already record that outcome.
		served := false
		for _, entry := range entries {
			if managedUpdatePhaseFromSubject(entry.SubjectKey) != authority.ManagedUpdateCanaryServing {
				continue
			}
			terminal, err := decodeManagedUpdatePhaseRecord(entry, record, authority.ManagedUpdateCanaryServing)
			served = err == nil && terminal.Phase == authority.ManagedUpdateCanaryServing
		}
		if !served || target.Phase != ManagedUpdateSeatPrepared && target.Phase != ManagedUpdateSeatCanaryServing ||
			latest.OperationID != preparedEntry.OperationID && target.Phase != ManagedUpdateSeatCanaryServing {
			return false, nil
		}
	}
	if placementReader == nil {
		return false, errors.New("placement authority lacks exact placement history")
	}
	placementEntry, err := placementReader.ReadPlacementIntent(ctx, state.DatabaseID, state.PartitionID)
	if err != nil {
		return false, err
	}
	if placementEntry.Sequence != record.PlacementSequence {
		return false, nil
	}
	currentIntent, err := DecodeCommittedIntent(placementEntry.Payload)
	if err != nil {
		return false, err
	}
	return currentIntent.Generation == record.PlacementGeneration &&
		currentIntent.PayloadDigest() == record.PlacementPayloadDigest &&
		currentIntent.Generation == intent.PlacementGeneration &&
		currentIntent.PayloadDigest() == intent.PlacementPayloadDigest, nil
}

func readManagedRuntimeTarget(ctx context.Context, config Config, members MemberPinReader,
	terminal authority.TerminalIntentReader, reader managedUpdatePlacementReader, updates authority.ManagedUpdateReader,
	epoch uint64, desired host.Desired, registration host.Registration,
) (managedRuntimeTargetSnapshot, bool, error) {
	if desired.ManagedMember == nil || desired.Withdrawn || registration.ManagedPlacement == nil ||
		registration.ManagedMember == nil || registration.ManagedOCI == nil {
		return managedRuntimeTargetSnapshot{}, false, errors.New("managed runtime target is missing its host registration")
	}
	placementBinding := *registration.ManagedPlacement
	if _, err := terminal.ReadTerminalIntent(ctx, placementBinding.DatabaseID, placementBinding.PartitionID); err == nil {
		return managedRuntimeTargetSnapshot{}, false, authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return managedRuntimeTargetSnapshot{}, false, err
	}
	entry, err := reader.ReadPlacementIntent(ctx, placementBinding.DatabaseID, placementBinding.PartitionID)
	if err != nil {
		return managedRuntimeTargetSnapshot{}, false, err
	}
	intent, err := DecodeCommittedIntent(entry.Payload)
	if err != nil || intent.Generation != placementBinding.IntentGeneration ||
		intent.PayloadDigest() != placementBinding.IntentPayloadDigest ||
		intent.DatabaseID != placementBinding.DatabaseID || intent.PartitionID != placementBinding.PartitionID {
		return managedRuntimeTargetSnapshot{}, false, errors.New("managed runtime placement differs from its exact authority record")
	}
	stateVersion, err := members.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, placementBinding.SeatID)
	if err != nil {
		return managedRuntimeTargetSnapshot{}, false, err
	}
	state := stateVersion.State
	if state.CanonicalRosterRow.MemberID != desired.ManagedMember.Member.Scope.MemberID {
		return managedRuntimeTargetSnapshot{}, false, errors.New("managed runtime target member differs from its durable placement seat")
	}
	target := state.ManagedRuntimeTarget
	if target.OperationID == "" {
		return managedRuntimeTargetSnapshot{}, false, nil
	}
	if stateVersion.Revision == 0 || state.Validate() != nil || state.SchemaVersion != managedUpdateMemberStateSchemaVersion ||
		state.HostNode != desired.Node || state.HostGeneration != registration.Generation ||
		state.MemberID != placementBinding.SeatID || target.Phase == ManagedUpdateSeatHeld ||
		state.Stage != StagePreparedDesired && state.Stage != StageAwaitingHealthy && state.Stage != StageServing ||
		registration.ManagedOCI.InstanceID != state.InstanceID || registration.ManagedOCI.CreateKey != state.CreateKey ||
		registration.ManagedOCI.Owner != config.ManagedOwner ||
		registration.ManagedOCI.FleetGeneration != config.FleetGeneration {
		return managedRuntimeTargetSnapshot{}, false, errors.New("managed runtime target differs from the exact durable canary seat")
	}
	if updates == nil {
		return managedRuntimeTargetSnapshot{}, false, errors.New("placement authority lacks managed update history")
	}
	current, err := managedUpdatePrepareIsCurrent(ctx, config.Cell, updates, reader, state)
	if err != nil {
		return managedRuntimeTargetSnapshot{}, false, err
	}
	if !current {
		return managedRuntimeTargetSnapshot{}, false, errors.New("managed runtime update authority is no longer current")
	}
	if desired.Digest != target.ArtifactDigest || desired.Generation != target.DesiredGeneration ||
		desired.ManagedMember.SourceDigest != target.SourceDigest {
		return managedRuntimeTargetSnapshot{}, false, errors.New("managed runtime target differs from its durable canary pins")
	}
	seat, ok := managedSeatForMember(config, intent, state.Region, state.MemberID)
	if !ok {
		return managedRuntimeTargetSnapshot{}, false, errors.New("managed runtime target seat is not in the immutable placement")
	}
	want, err := managedMemberDesired(config, epoch, intent, state, seat)
	if err != nil || !sameManagedDesired(desired, want) {
		return managedRuntimeTargetSnapshot{}, false, errors.New("managed runtime target desired differs from its durable canary pins")
	}
	return managedRuntimeTargetSnapshot{placement: entry, member: stateVersion,
		artifact: AdmittedArtifact{Digest: target.ArtifactDigest, ManifestDigest: target.ManifestDigest, SourceDigest: target.SourceDigest}}, true, nil
}
