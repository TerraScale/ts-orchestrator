package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

type volumeInitMemberReader struct {
	member placement.VersionedMemberState
}

func (reader *volumeInitMemberReader) ReadMember(_ context.Context, databaseID, partitionID, seatID string) (placement.VersionedMemberState, error) {
	state := reader.member.State
	if state.DatabaseID != databaseID || state.PartitionID != partitionID || state.MemberID != seatID {
		return placement.VersionedMemberState{}, placement.ErrMemberNotFound
	}
	return reader.member, nil
}

func TestVolumeInitRequiresCurrentExactPlacementSeat(t *testing.T) {
	intentWire, err := protocol.EncodeJSON(testManagedPlacementIntent())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := placement.DecodeCommittedIntent(intentWire)
	if err != nil {
		t.Fatal(err)
	}
	seat := placement.Seat{MemberID: "00000000000E5NVMSGX0D07DPA", Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-1", Kind: placement.MemberPermanent}
	row, err := intent.RosterRowForSeat(seat)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := intent.RuntimeManifestForSeat(seat)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := intent.ManagedHostProfile(seat.Region)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := profile.ProfileDigest()
	if err != nil {
		t.Fatal(err)
	}
	rosterDigest, err := intent.CanonicalRosterDigest()
	if err != nil {
		t.Fatal(err)
	}
	state := placement.MemberState{
		SchemaVersion: 5, DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
		MemberID: seat.MemberID, Region: seat.Region, FailureDomain: seat.FailureDomain,
		Kind: seat.Kind, Stage: placement.StageAwaitingHealthy,
		CreateKey: "0000000000NQKJR630FYJ4DPE1", HostNode: "host-gru-a", InstanceID: "ocid1.instance.oc1..volume-init-test",
		VolumeID: "ocid1.volume.oc1..first", AttachmentID: "ocid1.volumeattachment.oc1..first",
		AttachmentDevice: "/dev/oracleoci/oraclevdb", AttachmentETag: "first-attachment-etag",
		HostAttempt: 1, IntentGeneration: intent.Generation, IntentPayloadDigest: intent.PayloadDigest(),
		ManagedHostProfile: profile, ManagedHostProfileDigest: profileDigest,
		CanonicalRosterRow: row, CanonicalRosterDigest: rosterDigest,
		AuthorityReference: intent.CanonicalRoster.Authority, RuntimeManifest: manifest,
		RuntimeManifestDigest: manifestDigest, DesiredGeneration: intent.Generation,
		HostGeneration: 1, OperationID: "000000000032ZPCV4RYZC2WXBX", UpdatedAt: time.Now().UTC(),
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("fixture placement seat is invalid: %v", err)
	}
	binding := host.ManagedMemberBinding{Scope: host.MemberScope{
		ClusterID: intent.CanonicalRoster.ClusterID, TenantID: intent.CanonicalRoster.TenantID,
		DatabaseID: intent.CanonicalRoster.DatabaseID, ShardID: intent.CanonicalRoster.ShardID,
		MemberID: row.MemberID, Incarnation: row.Incarnation,
	}, HostAttempt: state.HostAttempt}
	mountPath, err := host.ManagedMountPath(manifest.ManagedRuntimeRoot, binding)
	if err != nil {
		t.Fatal(err)
	}
	registration := host.Registration{Cell: "gru", Node: state.HostNode, Generation: state.HostGeneration,
		ManagedPlacement: &host.ManagedPlacementBinding{
			DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, SeatID: state.MemberID,
			IntentGeneration: state.IntentGeneration, IntentPayloadDigest: state.IntentPayloadDigest,
			CanonicalRosterDigest: rosterDigest, ManagedHostProfileDigest: profileDigest,
		},
		ManagedMember: &binding,
		ManagedOCI: &host.ManagedOCIBinding{Region: string(state.Region), InstanceID: state.InstanceID,
			Owner: "regional-owner", FleetGeneration: 1, CreateKey: state.CreateKey},
	}
	desired := host.Desired{Cell: "gru", Node: state.HostNode, Digest: manifest.ArtifactDigest,
		Generation: state.DesiredGeneration, ManagedMember: &host.ManagedMemberLaunch{
			OCI: *registration.ManagedOCI, Member: binding,
			Authority: host.MemberAuthority{
				Epoch: state.AuthorityReference.Epoch, ConfigurationID: state.AuthorityReference.ConfigurationID,
				CertificateSHA256: state.AuthorityReference.CertificateSHA256,
				TLSLeafSHA256:     row.TLSLeafSHA256,
			},
			SourceDigest: manifest.SourceDigest, VolumeID: state.VolumeID,
			AttachmentID: state.AttachmentID, AttachmentETag: state.AttachmentETag,
			ProcessMemoryBytes: profile.ProcessMemoryBytes, MemoryHeadroomBytes: profile.MemoryHeadroomBytes,
			CgroupMemoryMaxBytes: profile.CgroupMemoryMaxBytes, SystemReserveBytes: profile.SystemReserveBytes,
			Runtime: &host.ManagedRuntimePins{
				DevicePath: state.AttachmentDevice, MountPath: mountPath,
				FileSystemUUID: manifest.FileSystemUUID, FileSystemType: manifest.FileSystemType,
				TrustedKeySHA256:                    manifest.TrustedKeySHA256,
				ServerCertificateSHA256:             manifest.ServerCertificateSHA256,
				ServerPrivateKeySHA256:              manifest.ServerPrivateKeySHA256,
				ClientCARootsSHA256:                 manifest.ClientCARootsSHA256,
				ClientManagedMaterialManifestSHA256: manifest.ClientManagedMaterialManifestSHA256,
				LiveS3ConfigSHA256:                  manifest.LiveS3ConfigSHA256,
				LiveS3TargetSHA256:                  manifest.LiveS3TargetSHA256,
				LiveS3Credential:                    manifest.LiveS3Credential,
				ReplicationListenAddress:            manifest.ReplicationListenAddress,
				ReplicationPeerMemberID:             manifest.ReplicationPeerMemberID,
				ReplicationPeerAddress:              manifest.ReplicationPeerAddress,
				ReplicationServerCASHA256:           manifest.ReplicationServerCASHA256,
			},
		}}
	reader := &volumeInitMemberReader{member: placement.VersionedMemberState{State: state, Revision: 5}}
	if err := verifyCurrentVolumeInitSeat(t.Context(), reader, desired, registration); err != nil {
		t.Fatalf("current exact placement seat was rejected: %v", err)
	}
	mismatchedSQLPin := desired
	changedLaunch := *desired.ManagedMember
	changedRuntime := *changedLaunch.Runtime
	changedRuntime.SQLSchemaBundleSHA256 = strings.Repeat("a", 64)
	changedLaunch.Runtime = &changedRuntime
	mismatchedSQLPin.ManagedMember = &changedLaunch
	if err := verifyCurrentVolumeInitSeat(t.Context(), reader, mismatchedSQLPin, registration); err == nil {
		t.Fatal("volume-init preflight accepted a SQL bundle pin absent from the current placement manifest")
	}
	for _, test := range []struct {
		name   string
		change func(*placement.MemberState)
	}{
		{"volume replaced", func(s *placement.MemberState) { s.VolumeID = "ocid1.volume.oc1..replacement" }},
		{"attachment replaced", func(s *placement.MemberState) { s.AttachmentID = "ocid1.volumeattachment.oc1..replacement" }},
		{"attachment etag replaced", func(s *placement.MemberState) { s.AttachmentETag = "replacement-etag" }},
		{"device replaced", func(s *placement.MemberState) { s.AttachmentDevice = "/dev/oracleoci/oraclevdc" }},
		{"host attempt replaced", func(s *placement.MemberState) { s.HostAttempt++ }},
		{"desired generation advanced", func(s *placement.MemberState) { s.DesiredGeneration++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := state
			test.change(&changed)
			if err := changed.Validate(); err != nil {
				t.Fatalf("changed seat is not independently valid: %v", err)
			}
			reader.member.State = changed
			if err := verifyCurrentVolumeInitSeat(t.Context(), reader, desired, registration); err == nil {
				t.Fatal("previous signed desired matched a changed placement seat")
			}
		})
	}
}
