package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

type currentPlacementReader interface {
	ReadPlacementIntent(context.Context, string, string) (authority.LogEntry, error)
}

func admittedManagedMaterialProvider(service managedmaterial.PreparationService,
	placements currentPlacementReader,
) host.ManagedMaterialProvider {
	return func(ctx context.Context, desired host.Desired, registration host.Registration) (map[string][]byte, error) {
		if desired.ManagedMember == nil || desired.ManagedMember.Runtime == nil ||
			registration.ManagedPlacement == nil || registration.ManagedMember == nil ||
			registration.ManagedOCI == nil || desired.Withdrawn ||
			desired.ManagedMember.Member != *registration.ManagedMember ||
			desired.ManagedMember.OCI != *registration.ManagedOCI ||
			desired.ManagedMember.Member.HostAttempt != 1 {
			return nil, errors.New("managed material host binding is incomplete or stale")
		}
		placementBinding := *registration.ManagedPlacement
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
		if index < 0 || !desiredMaterialMatchesReceipt(desired, intent, receipt, index) {
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
		return files, nil
	}
}

func desiredMaterialMatchesReceipt(desired host.Desired, intent placement.Intent,
	receipt managedmaterial.PreparationReceipt, memberIndex int,
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
	if !found || desired.Digest != manifest.ArtifactDigest || launch.SourceDigest != manifest.SourceDigest ||
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
		runtime.ReplicationListenAddress == manifest.ReplicationListenAddress &&
		runtime.ReplicationPeerMemberID == manifest.ReplicationPeerMemberID &&
		runtime.ReplicationPeerAddress == manifest.ReplicationPeerAddress &&
		runtime.ReplicationServerCASHA256 == manifest.ReplicationServerCASHA256
}
