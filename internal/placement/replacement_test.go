package placement

import (
	"context"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

func lostMemberObservation(state MemberState) MemberObservation {
	return MemberObservation{DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, MemberID: state.MemberID,
		Region: state.Region, FailureDomain: state.FailureDomain, InstanceID: state.InstanceID,
		VolumeID: state.VolumeID, Stage: StageAwaitingRuntimeContract}
}

func completeLostEvidence(state MemberState) RetirementEvidence {
	return RetirementEvidence{DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, MemberID: state.MemberID,
		InstanceID: state.InstanceID, VolumeID: state.VolumeID, ReplicationHealthy: true, QuorumSafe: true,
		WriterStopped: true, WriterStopProof: oci.WriterStopEvidence("detached-and-terminated"), VolumeRetained: true}
}

func TestCanReplaceLostMemberGate(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	permanent := testMemberState(t, intent, Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}, StageAwaitingRuntimeContract)
	elastic := testMemberState(t, intent, Seat{MemberID: elasticMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic}, StageServing)
	survivor := lostMemberObservation(elastic)
	survivor.Stage, survivor.Healthy, survivor.CurrentSession = StageServing, true, true
	lost := lostMemberObservation(permanent)
	if allowed, reason := CanReplaceLostMember(intent, lost, []MemberObservation{survivor},
		completeLostEvidence(permanent)); !allowed {
		t.Fatalf("complete evidence refused: %s", reason)
	}
	for _, test := range []struct {
		name     string
		mutate   func(*MemberObservation, *MemberObservation, *RetirementEvidence)
		expected string
	}{
		{"still healthy", func(l *MemberObservation, _ *MemberObservation, _ *RetirementEvidence) { l.Healthy = true }, "candidate-not-lost"},
		{"serving stage", func(l *MemberObservation, _ *MemberObservation, _ *RetirementEvidence) { l.Stage = StageServing }, "candidate-not-lost"},
		{"no volume", func(l *MemberObservation, _ *MemberObservation, _ *RetirementEvidence) { l.VolumeID = "" }, "candidate-identity-missing"},
		{"survivor unhealthy", func(_ *MemberObservation, s *MemberObservation, _ *RetirementEvidence) { s.Healthy = false }, "no-serving-survivor"},
		{"survivor same domain", func(_ *MemberObservation, s *MemberObservation, _ *RetirementEvidence) {
			s.FailureDomain = "FAULT-DOMAIN-1"
		}, "survivor-anti-affinity-violated"},
		{"other instance", func(_ *MemberObservation, _ *MemberObservation, e *RetirementEvidence) {
			e.InstanceID = "0000000000V4MRM46HP1SNGDYW"
		}, "retirement-evidence-identity-mismatch"},
		{"replication", func(_ *MemberObservation, _ *MemberObservation, e *RetirementEvidence) { e.ReplicationHealthy = false }, "replication-health-unverified"},
		{"quorum", func(_ *MemberObservation, _ *MemberObservation, e *RetirementEvidence) { e.QuorumSafe = false }, "quorum-safety-unverified"},
		{"writer proof", func(_ *MemberObservation, _ *MemberObservation, e *RetirementEvidence) { e.WriterStopProof = nil }, "writer-stop-unverified"},
		{"volume", func(_ *MemberObservation, _ *MemberObservation, e *RetirementEvidence) { e.VolumeRetained = false }, "retained-volume-decision-unverified"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate, peer, evidence := lost, survivor, completeLostEvidence(permanent)
			test.mutate(&candidate, &peer, &evidence)
			if allowed, reason := CanReplaceLostMember(intent, candidate, []MemberObservation{peer}, evidence); allowed ||
				reason != test.expected {
				t.Fatalf("CanReplaceLostMember = %t %q, want %q", allowed, reason, test.expected)
			}
		})
	}
	// Scale-in retirement of the same lost member is still refused: the
	// seat is desired and only one other member would remain.
	if allowed, _ := CanRetire(intent, lost, []MemberObservation{survivor}, completeLostEvidence(permanent)); allowed {
		t.Fatal("CanRetire allowed retiring a desired seat")
	}
}

// servingSurvivor gives the elastic member a current serving report.
func servingSurvivor(t *testing.T, controller *Controller, intent Intent, state MemberState, status *host.HostStatus) {
	t.Helper()
	peer := intent.CanonicalRoster.Rows[0]
	mount, err := host.ManagedMountPath(state.RuntimeManifest.ManagedRuntimeRoot, controller.memberBinding(intent, state))
	if err != nil {
		t.Fatal(err)
	}
	proof := memberstatus.ServingProof{
		SchemaVersion: 1, Nonce: strings.Repeat("1", 32),
		Process: memberstatus.Process{PID: 1234, StartNonce: "00000000000064eeb57eb73c4a8035be"},
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
	status.Reports = []host.Report{{
		Cell: "gru", Node: state.HostNode, Environment: "production", Role: "terrabase",
		Digest: state.RuntimeManifest.ArtifactDigest, Generation: state.DesiredGeneration,
		State: "running", ObservedAt: time.Now().UTC(),
		Managed: &host.ManagedRuntimeReport{
			Member: controller.memberBinding(intent, state),
			Authority: host.MemberAuthority{
				Epoch: proof.Authority.Epoch, ConfigurationID: proof.Authority.ConfigurationID,
				CertificateSHA256: proof.Authority.CertificateSHA256, TLSLeafSHA256: proof.Authority.TLSLeafSHA256,
			},
			OCI: *status.Registration.ManagedOCI, VolumeID: state.VolumeID,
			AttachmentID: state.AttachmentID, AttachmentETag: state.AttachmentETag,
			FileSystemUUID: state.RuntimeManifest.FileSystemUUID, FileSystemType: state.RuntimeManifest.FileSystemType,
			MountDevice: state.AttachmentDevice, MountPath: mount, MountID: 23,
			ProcessPID: proof.Process.PID, ProcessStart: "12345", ProcessCgroup: "/terrabase",
			ProcessBootID: proof.Process.StartNonce, StorageRecovered: true, ListenerReady: true,
			ServingProof: &proof,
		},
	}}
}

func TestControllerReplacesLostMemberOnlyWithEvidenceAfterGrace(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	permanentSeat := Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}
	elasticSeat := Seat{MemberID: elasticMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic}
	store := newPlacementMemoryStore(t, intent)
	lost := testMemberState(t, intent, permanentSeat, StageAwaitingRuntimeContract)
	lost.UpdatedAt = time.Now().UTC().Add(-time.Hour)
	store.members[permanentSeat.MemberID] = VersionedMemberState{State: lost, Revision: 1}
	survivor := testMemberState(t, intent, elasticSeat, StageServing)
	survivor.AttachmentDevice, survivor.AttachmentETag = "/dev/sdb", "attachment-etag"
	store.members[elasticSeat.MemberID] = VersionedMemberState{State: survivor, Revision: 1}
	instances := attachedInstances(t, intent)[1:] // the permanent member's host is gone.
	instances[0].Attachments[0].Device = survivor.AttachmentDevice
	instances[0].Attachments[0].IsPvEncryptionInTransitEnabled = true
	fleet := &placementTestFleet{instances: instances}
	statuses := admittedStatuses(t, intent)[1:]
	hosts := &placementTestHosts{statuses: statuses}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, hosts, func(reason string) { holds = append(holds, reason) })
	servingSurvivor(t, controller, intent, survivor, &hosts.statuses[0])

	tick := func() MemberState {
		t.Helper()
		holds = nil
		if err := controller.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := store.members[elasticSeat.MemberID].State.Stage; got != StageServing {
			t.Fatalf("survivor stage = %q", got)
		}
		return store.members[permanentSeat.MemberID].State
	}
	// Without an evidence source the lost member is held, as before.
	if state := tick(); state.Stage != StageAwaitingRuntimeContract || state.HostAttempt != 1 {
		t.Fatalf("no evidence source state = %+v", state)
	}
	var evidence RetirementEvidence
	complete := false
	controller.config.LostMemberEvidence = func(_ context.Context, state MemberState) (RetirementEvidence, bool, error) {
		if state.MemberID != permanentSeat.MemberID {
			t.Fatalf("evidence requested for %s", state.MemberID)
		}
		return evidence, complete, nil
	}
	// The first pass only records when the host was first seen missing; the
	// grace runs from that moment, not from the member's last write.
	lostAt := time.Now().UTC()
	controller.now = func() time.Time { return lostAt }
	if state := tick(); state.Stage != StageAwaitingRuntimeContract || !state.HostLostAt.Equal(lostAt) {
		t.Fatalf("host loss not recorded: %+v", state)
	}
	if state := tick(); state.HostAttempt != 1 || strings.Contains(strings.Join(holds, "\n"), "replacement") {
		t.Fatalf("replacement considered within the grace of a fresh loss: %+v holds=%v", state, holds)
	}
	controller.now = func() time.Time { return lostAt.Add(DefaultLostMemberGrace + time.Minute) }
	if state := tick(); state.Stage != StageAwaitingRuntimeContract ||
		!strings.Contains(strings.Join(holds, "\n"), "replacement awaits") {
		t.Fatalf("incomplete evidence state = %+v holds=%v", state, holds)
	}
	evidence, complete = completeLostEvidence(lost), true
	evidence.WriterStopProof = nil
	if state := tick(); state.Stage != StageAwaitingRuntimeContract ||
		!strings.Contains(strings.Join(holds, "\n"), "writer-stop-unverified") {
		t.Fatalf("missing writer stop state = %+v holds=%v", state, holds)
	}
	// Within the grace the member is not replaced even with full evidence.
	evidence = completeLostEvidence(lost)
	controller.config.LostMemberGrace = 2 * time.Hour
	if state := tick(); state.Stage != StageAwaitingRuntimeContract || state.HostAttempt != 1 {
		t.Fatalf("within grace state = %+v", state)
	}
	controller.config.LostMemberGrace = 0
	state := tick()
	if state.Stage != StagePreparedHost || state.HostAttempt != 2 || state.CreateKey != hostCreateKey(intent, permanentSeat, 2) ||
		state.VolumeID != lost.VolumeID || state.InstanceID != "" || state.AttachmentID != "" || state.HostGeneration != 0 ||
		state.RuntimeManifestDigest != lost.RuntimeManifestDigest {
		t.Fatalf("replacement state = %+v", state)
	}
	if fleet.ensureCalls != 0 || fleet.terminateCalls != 0 {
		t.Fatalf("replacement decision touched OCI directly: ensure=%d terminate=%d", fleet.ensureCalls, fleet.terminateCalls)
	}
}

func TestControllerNeverReplacesObservedLostHost(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := newPlacementMemoryStore(t, intent)
	permanent := store.members[permanentMember(oci.RegionGRU)]
	permanent.State.UpdatedAt = time.Now().UTC().Add(-time.Hour)
	store.members[permanentMember(oci.RegionGRU)] = permanent
	fleet := &placementTestFleet{instances: attachedInstances(t, intent)}
	hosts := &placementTestHosts{}
	controller := startTestPlacementController(t, store, fleet, hosts, nil)
	called := false
	controller.config.LostMemberEvidence = func(context.Context, MemberState) (RetirementEvidence, bool, error) {
		called = true
		return completeLostEvidence(permanent.State), true, nil
	}
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if called || store.members[permanentMember(oci.RegionGRU)].State.HostAttempt != 1 {
		t.Fatal("a still-observed host was considered for replacement")
	}
}
