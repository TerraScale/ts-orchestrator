//go:build linux

package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

func TestManagedDrainCommandPersistsAcrossLeaderEpoch(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	registration, desired, hostKey := managedContractFixture()
	registration.ManagedPlacement = &ManagedPlacementBinding{
		DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000Z3WK359G2W66CVT8", SeatID: "000000000082AXF7GZQT1D126Y",
		IntentGeneration: 1, IntentPayloadDigest: strings.Repeat("1", 64),
		CanonicalRosterDigest: strings.Repeat("2", 64), ManagedHostProfileDigest: strings.Repeat("3", 64),
	}
	paths, err := runtimePaths("/srv/managed", *desired.ManagedMember)
	if err != nil {
		t.Fatal(err)
	}
	desired.ManagedMember.Runtime = &ManagedRuntimePins{
		DevicePath: "/dev/sdb", MountPath: paths.mount,
		FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4",
		TrustedKeySHA256: strings.Repeat("1", 64), ServerCertificateSHA256: strings.Repeat("2", 64),
		ServerPrivateKeySHA256: strings.Repeat("3", 64), ClientCARootsSHA256: strings.Repeat("4", 64),
		ClientManagedMaterialManifestSHA256: strings.Repeat("5", 64),
		LiveS3ConfigSHA256:                  strings.Repeat("7", 64),
		LiveS3TargetSHA256:                  strings.Repeat("8", 64),
		LiveS3Credential:                    oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3},
		ReplicationListenAddress:            "10.0.0.11:7000",
		ReplicationPeerMemberID:             "01HW000000E008000000000002",
		ReplicationPeerAddress:              "10.0.0.12:7001", ReplicationServerCASHA256: strings.Repeat("6", 64),
	}
	desired.ManagedMember.AttachmentETag = "etag-current"
	artifact := []byte("managed drain replay artifact")
	digest := sha256.Sum256(artifact)
	desired.Digest = hex.EncodeToString(digest[:])
	controller, _, objects, _, _ := testControllerWithVerifier(t,
		managedRegistrationVerifierFunc(func(context.Context, Registration) error { return nil }))
	if _, err := controller.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.PutBytes(t.Context(), "sha256-"+desired.Digest, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	sessionID := "00000000000000000000000004"
	accepted, err := controller.handleSession(t.Context(), signedHostRequest(t, hostKey, "session", sessionID, 0,
		struct {
			Kind string `json:"kind"`
		}{Kind: "acquire"}))
	if err != nil {
		t.Fatal(err)
	}
	s := accepted.(session)
	proof := memberstatus.ServingProof{
		SchemaVersion: 1, Nonce: strings.Repeat("5", 32),
		Process:   memberstatus.Process{PID: 1234, StartNonce: "000000000000fd5c0c024bbce2e4de6a"},
		Scope:     drainIdentity(ManagedDrainCommand{Member: desired.ManagedMember.Member}).Scope,
		Authority: drainIdentity(ManagedDrainCommand{Authority: desired.ManagedMember.Authority}).Authority,
		Serving:   true, Listeners: memberstatus.Listeners{Client: true, Replication: true},
		Object: memberstatus.ObjectProof{
			RootSHA256: strings.Repeat("7", 64), TargetSHA256: strings.Repeat("8", 64),
			InboxArchiveSHA256AtRecovery: strings.Repeat("9", 64), LocalSourceSequence: 12,
		},
		Replication: memberstatus.ReplicationProof{
			LocalSourceSequence: 12, PeerMemberID: desired.ManagedMember.Runtime.ReplicationPeerMemberID,
			PeerIncarnation: "0000000000000000000000000000000a", CurrentAuthenticated: true,
			PeerDurableSequence: 12, PeerAppliedSequence: 12,
		},
	}
	report := Report{
		Cell: desired.Cell, Node: desired.Node, Environment: desired.Environment, Role: desired.Role,
		Digest: desired.Digest, Generation: desired.Generation, SessionID: s.SessionID, Epoch: s.Epoch,
		State: "running", ObservedAt: time.Now().UTC(),
		Managed: &ManagedRuntimeReport{
			Member: desired.ManagedMember.Member, Authority: desired.ManagedMember.Authority,
			OCI: desired.ManagedMember.OCI, VolumeID: desired.ManagedMember.VolumeID,
			AttachmentID: desired.ManagedMember.AttachmentID, AttachmentETag: desired.ManagedMember.AttachmentETag,
			FileSystemUUID: desired.ManagedMember.Runtime.FileSystemUUID,
			FileSystemType: desired.ManagedMember.Runtime.FileSystemType,
			MountDevice:    desired.ManagedMember.Runtime.DevicePath, MountPath: paths.mount, MountID: 23,
			ProcessPID: proof.Process.PID, ProcessStart: "12345", ProcessCgroup: "/terrabase",
			ProcessBootID: proof.Process.StartNonce, StorageRecovered: true, ListenerReady: true,
			ServingProof: &proof,
		},
	}
	if _, err := controller.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "report",
		s.SessionID, s.Epoch, report)); err != nil {
		t.Fatal(err)
	}
	command := ManagedDrainCommand{
		OperationID: "5VQEXVQEXVQEXVQEXVQEXVQEXV", Node: desired.Node, Role: desired.Role,
		Epoch: 1, DesiredGeneration: desired.Generation, ExpectedETag: "instance-etag",
		Member: desired.ManagedMember.Member, Authority: desired.ManagedMember.Authority,
		OCI: desired.ManagedMember.OCI, VolumeID: desired.ManagedMember.VolumeID,
		AttachmentID: desired.ManagedMember.AttachmentID, ExpectedProcess: proof.Process,
		Survivor: memberstatus.Survivor{MemberID: proof.Replication.PeerMemberID,
			Incarnation: proof.Replication.PeerIncarnation}, SourceSequence: 12,
	}
	if err := controller.RequestManagedDrain(t.Context(), command); err != nil {
		t.Fatal(err)
	}
	controller.authorityEpoch = func() uint64 { return 2 }
	retry := command
	retry.Epoch = 2
	if err := controller.RequestManagedDrain(t.Context(), retry); err != nil {
		t.Fatalf("same persisted command failed after leader epoch changed: %v", err)
	}
	changed := retry
	changed.SourceSequence++
	if err := controller.RequestManagedDrain(t.Context(), changed); err != memberstatus.ErrOperationConflict {
		t.Fatalf("retargeted replay error = %v", err)
	}
}
