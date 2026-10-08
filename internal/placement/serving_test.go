package placement

import (
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

func TestServingStageRequiresCurrentNativeAndNamedSurvivor(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seat := Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}
	state := testMemberState(t, intent, seat, StageAwaitingHealthy)
	store := newPlacementMemoryStore(t, intent)
	store.members[seat.MemberID] = VersionedMemberState{State: state, Revision: 1}
	instances := attachedInstances(t, intent)
	instances[0].Attachments[0].Device = state.AttachmentDevice
	instances[0].Attachments[0].IsPvEncryptionInTransitEnabled = true
	fleet := &placementTestFleet{instances: instances}
	statuses := admittedStatuses(t, intent)
	hosts := &placementTestHosts{statuses: statuses}
	controller := startTestPlacementController(t, store, fleet, hosts, nil)
	peer := intent.CanonicalRoster.Rows[1]
	mount, err := host.ManagedMountPath(state.RuntimeManifest.ManagedRuntimeRoot, controller.memberBinding(intent, state))
	if err != nil {
		t.Fatal(err)
	}
	proof := memberstatus.ServingProof{
		SchemaVersion: 1, Nonce: strings.Repeat("1", 32),
		Process: memberstatus.Process{PID: 1234, StartNonce: "0000000000CKQBAZNQ7H580DDY"},
		Scope: memberstatus.Scope{
			ClusterID: intent.CanonicalRoster.ClusterID, TenantID: intent.CanonicalRoster.TenantID,
			DatabaseID: intent.CanonicalRoster.DatabaseID, ShardID: intent.CanonicalRoster.ShardID,
			MemberID: state.CanonicalRosterRow.MemberID, Incarnation: state.CanonicalRosterRow.Incarnation,
		},
		Authority: memberstatus.Authority{
			Epoch: state.AuthorityReference.Epoch, ConfigurationID: state.AuthorityReference.ConfigurationID,
			CertificateSHA256: state.AuthorityReference.CertificateSHA256,
			TLSLeafSHA256:     state.CanonicalRosterRow.TLSLeafSHA256,
		},
		Serving: true, Listeners: memberstatus.Listeners{Client: true, Replication: true},
		Object: memberstatus.ObjectProof{
			RootSHA256: strings.Repeat("3", 64), TargetSHA256: strings.Repeat("4", 64),
			InboxArchiveSHA256AtRecovery: strings.Repeat("5", 64), LocalSourceSequence: 12,
			RemoteInboxDurableSequence: 9, RemoteAppliedSequence: 9,
		},
		Replication: memberstatus.ReplicationProof{
			LocalSourceSequence: 12, PeerMemberID: peer.MemberID, PeerIncarnation: peer.Incarnation,
			CurrentAuthenticated: true, PeerDurableSequence: 12, PeerAppliedSequence: 12,
			LocalInboxDurableSequence: 9, LocalInboxAppliedSequence: 9,
		},
	}
	statuses[0].Reports = []host.Report{{
		Cell: "gru", Node: state.HostNode, Environment: "production", Role: "terrabase",
		Digest: state.RuntimeManifest.ArtifactDigest, Generation: state.DesiredGeneration,
		State: "running", ObservedAt: time.Now().UTC(),
		Managed: &host.ManagedRuntimeReport{
			Member: controller.memberBinding(intent, state),
			Authority: host.MemberAuthority{
				Epoch: proof.Authority.Epoch, ConfigurationID: proof.Authority.ConfigurationID,
				CertificateSHA256: proof.Authority.CertificateSHA256, TLSLeafSHA256: proof.Authority.TLSLeafSHA256,
			},
			OCI: *statuses[0].Registration.ManagedOCI, VolumeID: state.VolumeID,
			AttachmentID: state.AttachmentID, AttachmentETag: state.AttachmentETag,
			FileSystemUUID: state.RuntimeManifest.FileSystemUUID, FileSystemType: state.RuntimeManifest.FileSystemType,
			MountDevice: state.AttachmentDevice, MountPath: mount, MountID: 23,
			ProcessPID: proof.Process.PID, ProcessStart: "12345", ProcessCgroup: "/terrabase",
			ProcessBootID: proof.Process.StartNonce, StorageRecovered: true, ListenerReady: true,
			ServingProof: &proof,
		},
	}}
	hosts.statuses = statuses
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := store.members[seat.MemberID].State.Stage; got != StageServing {
		t.Fatalf("valid native proof stage = %q", got)
	}
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := store.members[seat.MemberID].State.Stage; got != StageServing {
		t.Fatalf("current proof was not retained: %q", got)
	}
	proof.Replication.PeerAppliedSequence = 11
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := store.members[seat.MemberID].State.Stage; got != StageAwaitingRuntimeContract {
		t.Fatalf("stale peer applied frontier retained serving: %q", got)
	}
}
