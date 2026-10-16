package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

// verifyCurrentVolumeInitSeat binds the signed desired to the current durable
// placement seat. Enrollment also reads this seat, but must run before the
// volume is created, so its registration check cannot require these pins.
func verifyCurrentVolumeInitSeat(ctx context.Context, members placement.MemberPinReader,
	desired host.Desired, registration host.Registration, runtimeTargets ...managedRuntimeTargetVerifier,
) error {
	if members == nil || desired.ManagedMember == nil || desired.ManagedMember.Runtime == nil ||
		registration.ManagedPlacement == nil || registration.ManagedOCI == nil || registration.ManagedMember == nil {
		return errors.New("managed volume placement inspection is unavailable")
	}
	binding := *registration.ManagedPlacement
	versioned, err := members.ReadMember(ctx, binding.DatabaseID, binding.PartitionID, binding.SeatID)
	if err != nil {
		return fmt.Errorf("read current volume placement seat: %w", err)
	}
	state := versioned.State
	launch := *desired.ManagedMember
	manifest, effectiveManifest, runtime := state.RuntimeManifest, state.EffectiveRuntimeManifest(), launch.Runtime
	mountPath, err := host.ManagedMountPath(manifest.ManagedRuntimeRoot, launch.Member)
	if err != nil {
		return fmt.Errorf("derive current volume mount path: %w", err)
	}
	if versioned.Revision == 0 || state.Validate() != nil ||
		state.Stage != placement.StagePreparedDesired && state.Stage != placement.StageAwaitingHealthy &&
			state.Stage != placement.StageServing ||
		state.DatabaseID != binding.DatabaseID || state.PartitionID != binding.PartitionID ||
		state.MemberID != binding.SeatID || state.HostNode != registration.Node ||
		state.IntentGeneration != binding.IntentGeneration ||
		state.IntentPayloadDigest != binding.IntentPayloadDigest ||
		state.CanonicalRosterDigest != binding.CanonicalRosterDigest ||
		state.ManagedHostProfileDigest != binding.ManagedHostProfileDigest ||
		state.HostGeneration != registration.Generation ||
		state.CreateKey != launch.OCI.CreateKey || state.HostAttempt != launch.Member.HostAttempt ||
		state.InstanceID != launch.OCI.InstanceID || state.Region != oci.Region(launch.OCI.Region) ||
		state.VolumeID != launch.VolumeID || state.AttachmentID != launch.AttachmentID ||
		state.AttachmentETag != launch.AttachmentETag ||
		state.AttachmentDevice != launch.Runtime.DevicePath ||
		state.DesiredGeneration != desired.Generation ||
		effectiveManifest.ArtifactDigest != desired.Digest || effectiveManifest.SourceDigest != launch.SourceDigest ||
		manifest.FileSystemUUID != runtime.FileSystemUUID || manifest.FileSystemType != runtime.FileSystemType ||
		mountPath != runtime.MountPath ||
		manifest.TrustedKeySHA256 != runtime.TrustedKeySHA256 ||
		manifest.ServerCertificateSHA256 != runtime.ServerCertificateSHA256 ||
		manifest.ServerPrivateKeySHA256 != runtime.ServerPrivateKeySHA256 ||
		manifest.ClientCARootsSHA256 != runtime.ClientCARootsSHA256 ||
		manifest.ClientManagedMaterialManifestSHA256 != runtime.ClientManagedMaterialManifestSHA256 ||
		manifest.SQLSchemaBundleSHA256 != runtime.SQLSchemaBundleSHA256 ||
		manifest.LiveS3ConfigSHA256 != runtime.LiveS3ConfigSHA256 ||
		manifest.LiveS3TargetSHA256 != runtime.LiveS3TargetSHA256 ||
		manifest.LiveS3Credential != runtime.LiveS3Credential ||
		manifest.ReplicationListenAddress != runtime.ReplicationListenAddress ||
		manifest.ReplicationPeerMemberID != runtime.ReplicationPeerMemberID ||
		manifest.ReplicationPeerAddress != runtime.ReplicationPeerAddress ||
		manifest.ReplicationServerCASHA256 != runtime.ReplicationServerCASHA256 ||
		state.AuthorityReference.Epoch != launch.Authority.Epoch ||
		state.AuthorityReference.ConfigurationID != launch.Authority.ConfigurationID ||
		state.AuthorityReference.CertificateSHA256 != launch.Authority.CertificateSHA256 ||
		state.CanonicalRosterRow.TLSLeafSHA256 != launch.Authority.TLSLeafSHA256 ||
		state.CanonicalRosterRow.MemberID != launch.Member.Scope.MemberID ||
		state.CanonicalRosterRow.Incarnation != launch.Member.Scope.Incarnation ||
		state.ManagedHostProfile.ProcessMemoryBytes != launch.ProcessMemoryBytes ||
		state.ManagedHostProfile.MemoryHeadroomBytes != launch.MemoryHeadroomBytes ||
		state.ManagedHostProfile.CgroupMemoryMaxBytes != launch.CgroupMemoryMaxBytes ||
		state.ManagedHostProfile.SystemReserveBytes != launch.SystemReserveBytes {
		return errors.New("managed volume desired differs from current placement seat")
	}
	if state.ManagedRuntimeTarget.OperationID != "" {
		if len(runtimeTargets) != 1 || runtimeTargets[0] == nil {
			return errors.New("managed volume canary lacks its current signed update verifier")
		}
		valid, err := runtimeTargets[0](ctx, desired, registration)
		if err != nil || !valid {
			return errors.New("managed volume canary is not authorized by its current signed update")
		}
	} else if desired.Digest != manifest.ArtifactDigest || launch.SourceDigest != manifest.SourceDigest {
		return errors.New("managed volume desired differs from immutable placement runtime")
	}
	return nil
}
