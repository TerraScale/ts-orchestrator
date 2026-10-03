package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

type currentPlacementReader interface {
	ReadPlacementIntent(context.Context, string, string) (authority.LogEntry, error)
}

type managedRuntimeTargetVerifier func(context.Context, host.Desired, host.Registration) (bool, error)

func admittedManagedMaterialProvider(service managedmaterial.PreparationService,
	placements currentPlacementReader,
	members placement.MemberPinReader,
	credentials managedmaterial.CredentialService,
	runtimeTarget managedRuntimeTargetVerifier,
) host.ManagedMaterialProvider {
	return func(ctx context.Context, desired host.Desired, registration host.Registration) (map[string][]byte, error) {
		if desired.ManagedMember == nil || desired.ManagedMember.Runtime == nil ||
			registration.ManagedPlacement == nil || registration.ManagedMember == nil ||
			registration.ManagedOCI == nil || desired.Withdrawn || members == nil ||
			desired.ManagedMember.Member != *registration.ManagedMember ||
			desired.ManagedMember.OCI != *registration.ManagedOCI ||
			desired.ManagedMember.Member.HostAttempt == 0 {
			return nil, errors.New("managed material host binding is incomplete or stale")
		}
		placementBinding := *registration.ManagedPlacement
		// The host attempt must be the seat's exact current durable attempt
		// on this node and instance: attempt one for an initial member, the
		// next attempt after a fenced replacement. A superseded attempt never
		// receives material.
		versioned, err := members.ReadMember(ctx, placementBinding.DatabaseID, placementBinding.PartitionID, placementBinding.SeatID)
		if err != nil {
			return nil, fmt.Errorf("read current managed seat: %w", err)
		}
		if seat := versioned.State; versioned.Revision == 0 ||
			seat.HostAttempt != desired.ManagedMember.Member.HostAttempt || seat.HostNode != registration.Node ||
			seat.InstanceID != registration.ManagedOCI.InstanceID || seat.CreateKey != registration.ManagedOCI.CreateKey {
			return nil, errors.New("managed material host attempt is not the seat's current durable attempt")
		}
		entry, err := placements.ReadPlacementIntent(ctx, placementBinding.DatabaseID, placementBinding.PartitionID)
		if err != nil {
			return nil, err
		}
		if entry.Kind != authority.MutationPlacementIntent || entry.Sequence == 0 ||
			entry.SubjectKey != placementBinding.DatabaseID+"."+placementBinding.PartitionID {
			return nil, errors.New("managed material current placement entry is invalid")
		}
		intent, err := placement.DecodeCommittedIntent(entry.Payload)
		if err != nil || intent.PayloadDigest() != placementBinding.IntentPayloadDigest ||
			intent.Generation != placementBinding.IntentGeneration {
			return nil, errors.New("managed material current placement changed")
		}
		receipt, bundle, err := service.CurrentBundle(ctx, intent.DatabaseID, intent.PartitionID)
		if err != nil {
			return nil, err
		}
		if err := managedmaterial.VerifyIntentAgainstReceipt(intent, receipt); err != nil {
			return nil, err
		}
		memberID := desired.ManagedMember.Member.Scope.MemberID
		index := -1
		for candidate, member := range receipt.Spec.Members {
			if member.MemberID == memberID && member.SeatID == placementBinding.SeatID {
				index = candidate
				break
			}
		}
		if index < 0 {
			return nil, managedmaterial.ErrMaterialConflict
		}
		updatedRuntime := false
		if !desiredMatchesInitialRuntime(desired, intent, placementBinding.SeatID) {
			if runtimeTarget == nil {
				return nil, managedmaterial.ErrMaterialConflict
			}
			updatedRuntime, err = runtimeTarget(ctx, desired, registration)
			if err != nil || !updatedRuntime {
				return nil, managedmaterial.ErrMaterialConflict
			}
		}
		if !desiredMaterialMatchesReceipt(desired, intent, receipt, index, updatedRuntime) {
			return nil, managedmaterial.ErrMaterialConflict
		}
		files := make(map[string][]byte, len(bundle.Members[index].Files))
		for name, file := range bundle.Members[index].Files {
			want := receipt.Members[index].Files[name]
			sum := sha256.Sum256(file.Contents)
			if want != hex.EncodeToString(sum[:]) || file.SHA256 != want || len(file.Contents) == 0 {
				return nil, managedmaterial.ErrMaterialConflict
			}
			files[name] = bytes.Clone(file.Contents)
		}
		state, _, err := credentials.Current(ctx, intent.DatabaseID, intent.PartitionID)
		if err != nil {
			return nil, err
		}
		wire, err := protocol.EncodeJSON(state)
		if err != nil {
			return nil, err
		}
		files["client-credentials-current.json"] = wire
		return files, nil
	}
}

func desiredMatchesInitialRuntime(desired host.Desired, intent placement.Intent, seatID string) bool {
	launch := desired.ManagedMember
	if launch == nil {
		return false
	}
	for _, manifest := range intent.RuntimeManifests {
		if manifest.SeatID == seatID && slices.Contains(intent.ActiveRegions, manifest.Region) {
			return desired.Digest == manifest.ArtifactDigest && launch.SourceDigest == manifest.SourceDigest
		}
	}
	return false
}

func desiredMaterialMatchesReceipt(desired host.Desired, intent placement.Intent,
	receipt managedmaterial.PreparationReceipt, memberIndex int, updatedRuntime bool,
) bool {
	launch := desired.ManagedMember
	if launch == nil || launch.Runtime == nil || memberIndex < 0 || memberIndex >= len(receipt.Spec.Members) {
		return false
	}
	seat := receipt.Spec.Members[memberIndex]
	var manifest placement.RuntimeManifest
	found := false
	for _, candidate := range intent.RuntimeManifests {
		if candidate.SeatID == seat.SeatID && slices.Contains(intent.ActiveRegions, candidate.Region) {
			manifest, found = candidate, true
			break
		}
	}
	if !found || !updatedRuntime && (desired.Digest != manifest.ArtifactDigest || launch.SourceDigest != manifest.SourceDigest) ||
		launch.Authority.Epoch != intent.CanonicalRoster.Authority.Epoch ||
		launch.Authority.ConfigurationID != receipt.AuthorityConfigurationID ||
		launch.Authority.CertificateSHA256 != receipt.AuthoritySHA256 ||
		launch.Authority.TLSLeafSHA256 != receipt.Members[memberIndex].TLSLeafSHA256 {
		return false
	}
	scope := launch.Member.Scope
	if scope.ClusterID != receipt.Spec.Scope.ClusterID || scope.TenantID != receipt.Spec.Scope.TenantID ||
		scope.DatabaseID != receipt.Spec.Scope.DatabaseID || scope.ShardID != receipt.Spec.Scope.ShardID ||
		scope.MemberID != seat.MemberID || scope.Incarnation != seat.Incarnation {
		return false
	}
	runtime := launch.Runtime
	return runtime.TrustedKeySHA256 == manifest.TrustedKeySHA256 &&
		runtime.ServerCertificateSHA256 == manifest.ServerCertificateSHA256 &&
		runtime.ServerPrivateKeySHA256 == manifest.ServerPrivateKeySHA256 &&
		runtime.ClientCARootsSHA256 == manifest.ClientCARootsSHA256 &&
		runtime.ClientManagedMaterialManifestSHA256 == manifest.ClientManagedMaterialManifestSHA256 &&
		runtime.SQLSchemaBundleSHA256 == manifest.SQLSchemaBundleSHA256 &&
		runtime.LiveS3ConfigSHA256 == manifest.LiveS3ConfigSHA256 &&
		runtime.LiveS3TargetSHA256 == manifest.LiveS3TargetSHA256 &&
		runtime.LiveS3Credential == manifest.LiveS3Credential &&
		runtime.BackupManifestSHA256 == manifest.BackupManifestSHA256 &&
		runtime.BackupS3ConfigSHA256 == manifest.BackupS3ConfigSHA256 &&
		runtime.BackupS3TargetSHA256 == manifest.BackupS3TargetSHA256 &&
		runtime.BackupS3CredentialSHA256 == manifest.BackupS3CredentialSHA256 &&
		runtime.BackupDataKeySHA256 == manifest.BackupDataKeySHA256 &&
		runtime.BackupOwner == manifest.BackupOwner &&
		runtime.BackupS3Credential == manifest.BackupS3Credential &&
		runtime.BackupDataKey == manifest.BackupDataKey &&
		runtime.ReplicationListenAddress == manifest.ReplicationListenAddress &&
		runtime.ReplicationPeerMemberID == manifest.ReplicationPeerMemberID &&
		runtime.ReplicationPeerAddress == manifest.ReplicationPeerAddress &&
		runtime.ReplicationServerCASHA256 == manifest.ReplicationServerCASHA256
}
