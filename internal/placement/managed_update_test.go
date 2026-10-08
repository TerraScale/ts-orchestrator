package placement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestManagedUpdateIntentValidatesSignedCompatibilityAndExactPredecessors(t *testing.T) {
	intent := validManagedUpdateIntent(t)
	if err := intent.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	promoted := intent
	promoted.Seats = slices.Clone(intent.Seats)
	for i := range promoted.Seats {
		if promoted.Seats[i].SeatID != promoted.CanarySeatID {
			promoted.Seats[i].ArtifactDigest = intent.CandidateArtifactDigest
		}
	}
	if err := promoted.Validate(); err != nil {
		t.Fatalf("a peer that already serves the candidate was rejected: %v", err)
	}
	if _, err := intent.Digest(); err != nil {
		t.Fatalf("Digest() error = %v", err)
	}

	statement, err := decodeManagedCompatibility(intent.CompatibilityEvidence)
	if err != nil {
		t.Fatalf("decodeManagedCompatibility() error = %v", err)
	}
	evidence, evidenceKey := signedManagedCompatibility(t, intent, statement)
	if err := protocol.VerifyEnvelope(evidence, protocol.EnvelopeScope{
		Region: intent.Cell, Kind: ManagedCompatibilityEnvelopeKind, Actor: evidence.Actor,
		OperationID: intent.OperationID, Generation: intent.CanaryDesiredGeneration, Epoch: evidence.Epoch,
	}, evidenceKey, time.Date(2026, time.September, 28, 12, 0, 30, 0, time.UTC),
		protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute}); err != nil {
		t.Fatalf("VerifyEnvelope() error = %v", err)
	}
}

func TestManagedUpdateIntentRejectsUnqualifiedOrMismatchedCompatibility(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ManagedUpdateIntent)
	}{
		{
			name: "missing mixed-version replication claim",
			mutate: func(intent *ManagedUpdateIntent) {
				intent.CompatibilityEvidence = resignManagedCompatibility(t, *intent, func(evidence *ManagedCompatibilityEvidence) {
					evidence.MixedVersionReplicationSupported = false
				})
			},
		},
		{
			name: "missing client-data compatibility claim",
			mutate: func(intent *ManagedUpdateIntent) {
				intent.CompatibilityEvidence = resignManagedCompatibility(t, *intent, func(evidence *ManagedCompatibilityEvidence) {
					evidence.ClientDataCompatibilitySupported = false
				})
			},
		},
		{
			name: "missing persistent-format read claim",
			mutate: func(intent *ManagedUpdateIntent) {
				intent.CompatibilityEvidence = resignManagedCompatibility(t, *intent, func(evidence *ManagedCompatibilityEvidence) {
					evidence.PersistentFormatReadSupported = false
				})
			},
		},
		{
			name: "missing persistent-format write claim",
			mutate: func(intent *ManagedUpdateIntent) {
				intent.CompatibilityEvidence = resignManagedCompatibility(t, *intent, func(evidence *ManagedCompatibilityEvidence) {
					evidence.PersistentFormatWriteSupported = false
				})
			},
		},
		{
			name: "wrong candidate manifest claim",
			mutate: func(intent *ManagedUpdateIntent) {
				intent.CompatibilityEvidence = resignManagedCompatibility(t, *intent, func(evidence *ManagedCompatibilityEvidence) {
					evidence.CandidateManifestDigest = strings.Repeat("e", 64)
				})
			},
		},
		{
			name: "wrong durability profile",
			mutate: func(intent *ManagedUpdateIntent) {
				intent.CompatibilityEvidence = resignManagedCompatibility(t, *intent, func(evidence *ManagedCompatibilityEvidence) {
					evidence.DurabilityProfileSHA256 = strings.Repeat("e", 64)
				})
			},
		},
		{
			name: "same-generation canary",
			mutate: func(intent *ManagedUpdateIntent) {
				intent.CanaryDesiredGeneration = intent.Seats[0].DesiredGeneration
			},
		},
		{
			name: "reordered seats",
			mutate: func(intent *ManagedUpdateIntent) {
				intent.Seats[0], intent.Seats[1] = intent.Seats[1], intent.Seats[0]
			},
		},
		{
			name: "peer on a third artifact",
			mutate: func(intent *ManagedUpdateIntent) {
				intent.Seats[1].ArtifactDigest = strings.Repeat("9", 64)
			},
		},
		{
			name: "canary already on the candidate",
			mutate: func(intent *ManagedUpdateIntent) {
				for i := range intent.Seats {
					if intent.Seats[i].SeatID == intent.CanarySeatID {
						intent.Seats[i].ArtifactDigest = intent.CandidateArtifactDigest
					}
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := validManagedUpdateIntent(t)
			test.mutate(&intent)
			if err := intent.Validate(); err == nil {
				t.Fatal("Validate() succeeded for invalid update intent")
			}
		})
	}
}

func TestManagedUpdateDurabilityDigestBindsRetainedFormatsAndTargets(t *testing.T) {
	profile := validManagedUpdateIntent(t).DurabilityProfile
	digest, err := profile.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}

	profile.Volumes[0].FileSystemType = "ext4"
	changed, err := profile.Digest()
	if err != nil {
		t.Fatalf("Digest() after valid format change error = %v", err)
	}
	if changed == digest {
		t.Fatal("Digest() did not change when a retained filesystem format changed")
	}
}

func TestManagedUpdateCanaryDeadlineIsAbsoluteAndFailClosed(t *testing.T) {
	preparedAt := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	target := ManagedRuntimeTarget{PreparedAt: preparedAt}
	deadline := preparedAt.Add(managedUpdateCanaryProofTimeout)

	for _, test := range []struct {
		name        string
		now         time.Time
		wantTimeout bool
		wantValid   bool
	}{
		{name: "before deadline", now: deadline.Add(-time.Nanosecond), wantValid: true},
		{name: "at deadline", now: deadline, wantTimeout: true, wantValid: true},
		{name: "after deadline", now: deadline.Add(time.Second), wantTimeout: true, wantValid: true},
		{name: "clock moved before preparation", now: preparedAt.Add(-time.Nanosecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			timedOut, clockValid := managedUpdateCanaryTiming(target, test.now)
			if timedOut != test.wantTimeout || clockValid != test.wantValid {
				t.Fatalf("managedUpdateCanaryTiming() = (%v, %v), want (%v, %v)",
					timedOut, clockValid, test.wantTimeout, test.wantValid)
			}
		})
	}

	invalid := target
	invalid.PreparedAt = time.Date(2026, time.September, 28, 12, 0, 0, 0, time.FixedZone("not-utc", 0))
	if timedOut, clockValid := managedUpdateCanaryTiming(invalid, deadline); timedOut || clockValid {
		t.Fatalf("non-UTC prepared time was accepted: timedOut=%v clockValid=%v", timedOut, clockValid)
	}
}

func TestManagedUpdateTerminalSeatRepairSurvivesLostCASAndRestart(t *testing.T) {
	for _, test := range []struct {
		name          string
		phase         authority.ManagedUpdatePhase
		outcome       string
		wantStage     MemberStage
		wantSeatPhase ManagedUpdateSeatPhase
	}{
		{name: "held", phase: authority.ManagedUpdateHeld, outcome: "candidate-proof-timeout",
			wantStage: StageAwaitingHealthy, wantSeatPhase: ManagedUpdateSeatHeld},
		{name: "canary serving", phase: authority.ManagedUpdateCanaryServing,
			outcome: string(authority.ManagedUpdateCanaryServing), wantStage: StageServing,
			wantSeatPhase: ManagedUpdateSeatCanaryServing},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManagedUpdateSeatOutcomeFixture(t)
			_, authorityLog := managedUpdateHistoryForFixture(t, &fixture, test.phase, test.outcome)
			fixture.controller.fencer = authorityLog
			failedCAS := false
			fixture.store.onCAS = func(next MemberState) error {
				if !failedCAS && next.ManagedRuntimeTarget.Phase == test.wantSeatPhase {
					failedCAS = true
					return ErrStoreConflict
				}
				return nil
			}
			members, err := fixture.store.ListMembers(t.Context(), fixture.intent.DatabaseID, fixture.intent.PartitionID)
			if err != nil {
				t.Fatal(err)
			}
			memberByID := make(map[string]VersionedMemberState, len(members))
			for _, member := range members {
				memberByID[member.State.MemberID] = member
			}
			acted, err := fixture.controller.reconcileManagedUpdate(t.Context(), 1, fixture.intent,
				[]Seat{{MemberID: fixture.canary.State.MemberID, Region: fixture.canary.State.Region,
					FailureDomain: fixture.canary.State.FailureDomain, Kind: fixture.canary.State.Kind}}, memberByID)
			if !failedCAS || !errors.Is(err, ErrStoreConflict) {
				t.Fatalf("first terminal history reconciliation = acted %v, err %v, failedCAS=%v; want injected store conflict", acted, err, failedCAS)
			}
			if current := fixture.store.members[fixture.canary.State.MemberID]; current.Revision != fixture.canary.Revision ||
				current.State.ManagedRuntimeTarget.Phase != ManagedUpdateSeatPrepared {
				t.Fatalf("failed terminal seat CAS changed durable state: %+v", current)
			}

			// A new controller instance has only the durable seat and retained
			// authority outcome; it repairs the same exact phase without replaying
			// a desired write or touching the peer.
			restarted := &Controller{config: fixture.controller.config, store: fixture.store,
				fencer: authorityLog}
			members, err = fixture.store.ListMembers(t.Context(), fixture.intent.DatabaseID, fixture.intent.PartitionID)
			if err != nil {
				t.Fatal(err)
			}
			memberByID = make(map[string]VersionedMemberState, len(members))
			for _, member := range members {
				memberByID[member.State.MemberID] = member
			}
			acted, err = restarted.reconcileManagedUpdate(t.Context(), 1, fixture.intent,
				[]Seat{{MemberID: fixture.canary.State.MemberID, Region: fixture.canary.State.Region,
					FailureDomain: fixture.canary.State.FailureDomain, Kind: fixture.canary.State.Kind}}, memberByID)
			if err != nil || !acted {
				t.Fatalf("terminal R3 history repair after restart = acted %v, err %v", acted, err)
			}
			current := fixture.store.members[fixture.canary.State.MemberID]
			if current.State.Stage != test.wantStage || current.State.ManagedRuntimeTarget.Phase != test.wantSeatPhase ||
				current.State.ManagedRuntimeTarget.Outcome != test.outcome ||
				!current.State.ManagedRuntimeTarget.PreparedAt.Equal(fixture.preparedAt) ||
				current.State.ManagedRuntimeTarget.OperationID != fixture.update.OperationID {
				t.Fatalf("terminal seat repair changed signed pins or used a new preparation time: %+v", current.State)
			}
			if peer := fixture.store.members[fixture.peer.State.MemberID]; !reflect.DeepEqual(peer, fixture.peer) {
				t.Fatalf("terminal seat repair changed the unchanged peer: got %+v want %+v", peer, fixture.peer)
			}
			casCalls := fixture.store.casCalls
			members, err = fixture.store.ListMembers(t.Context(), fixture.intent.DatabaseID, fixture.intent.PartitionID)
			if err != nil {
				t.Fatal(err)
			}
			memberByID = make(map[string]VersionedMemberState, len(members))
			for _, member := range members {
				memberByID[member.State.MemberID] = member
			}
			acted, err = restarted.reconcileManagedUpdate(t.Context(), 1, fixture.intent,
				[]Seat{{MemberID: fixture.canary.State.MemberID, Region: fixture.canary.State.Region,
					FailureDomain: fixture.canary.State.FailureDomain, Kind: fixture.canary.State.Kind}}, memberByID)
			wantActed := test.phase == authority.ManagedUpdateHeld
			if err != nil || acted != wantActed || fixture.store.casCalls != casCalls {
				t.Fatalf("idempotent terminal seat replay wrote again: CAS %d->%d err=%v",
					casCalls, fixture.store.casCalls, err)
			}
		})
	}
}

func TestManagedCanaryFinalServingVerifierRejectsProofAtDeadline(t *testing.T) {
	fixture := newManagedUpdateSeatOutcomeFixture(t)
	state := fixture.canary.State
	state.ManagedRuntimeTarget.PreparedAt = time.Now().UTC().Add(-managedUpdateCanaryProofTimeout)
	state.UpdatedAt = time.Now().UTC()
	fixture.canary.State = state
	controller := &Controller{config: fixture.controller.config, store: fixture.store, fencer: fixture.controller.fencer}
	err := controller.verifyManagedCanaryServing(t.Context(), 1, fixture.update, fixture.prepared, fixture.canary)
	if err == nil || !strings.Contains(err.Error(), "durable deadline") {
		t.Fatalf("late serving proof verifier error = %v, want durable deadline rejection", err)
	}
}

func TestManagedCanaryFinalServingVerifierRechecksDeadlineAfterProofReads(t *testing.T) {
	fixture := newManagedUpdateSeatOutcomeFixture(t)
	update, authorityLog := managedUpdateHistoryForFixture(t, &fixture, "", "")
	canary := fixture.canary.State
	beforeDeadline := time.Now().UTC().Truncate(time.Second)
	canary.ManagedRuntimeTarget.PreparedAt = beforeDeadline.Add(-managedUpdateCanaryProofTimeout + time.Second)
	canary.UpdatedAt = beforeDeadline
	fixture.canary = VersionedMemberState{State: canary, Revision: fixture.canary.Revision}
	fixture.store.members[canary.MemberID] = fixture.canary

	controller := managedCanaryServingController(t, fixture, update, authorityLog)
	clockCalls := 0
	controller.now = func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return beforeDeadline
		}
		return beforeDeadline.Add(2 * time.Second)
	}
	err := controller.verifyManagedCanaryServing(t.Context(), 1, update, authorityLog.preparedRecord, fixture.canary)
	if err == nil || !strings.Contains(err.Error(), "expired before the final authority commit") || clockCalls != 2 {
		t.Fatalf("serving verifier final deadline check = %v after %d clock reads, want final recheck rejection", err, clockCalls)
	}
}

func TestManagedCanaryTimeoutPersistsHeldWithoutHostOrStatusProof(t *testing.T) {
	for _, stage := range []MemberStage{StagePreparedDesired, StageAwaitingHealthy} {
		t.Run(string(stage), func(t *testing.T) {
			fixture := newManagedUpdateSeatOutcomeFixture(t)
			state := fixture.canary.State
			state.Stage = stage
			state.ManagedRuntimeTarget.PreparedAt = time.Now().UTC().Add(-managedUpdateCanaryProofTimeout - time.Second)
			state.UpdatedAt = time.Now().UTC()
			fixture.canary = VersionedMemberState{State: state, Revision: fixture.canary.Revision}
			fixture.store.members[state.MemberID] = fixture.canary
			_, authorityLog := managedUpdateHistoryForFixture(t, &fixture, "", "")
			controller := &Controller{config: fixture.controller.config, store: fixture.store, fencer: authorityLog}

			acted, err := controller.holdTimedOutManagedCanary(t.Context(), 1, fixture.intent, fixture.canary)
			if err != nil || !acted {
				t.Fatalf("holdTimedOutManagedCanary() = acted %v, err %v", acted, err)
			}
			current := fixture.store.members[state.MemberID]
			if current.State.ManagedRuntimeTarget.Phase != ManagedUpdateSeatHeld ||
				current.State.ManagedRuntimeTarget.Outcome != "candidate-proof-timeout" ||
				current.State.Stage != stage ||
				!current.State.ManagedRuntimeTarget.PreparedAt.Equal(state.ManagedRuntimeTarget.PreparedAt) ||
				authorityLog.committed.Phase != authority.ManagedUpdateHeld ||
				authorityLog.committed.Outcome != "candidate-proof-timeout" {
				t.Fatalf("proof deadline did not persist the matching R3 and seat Held result: seat=%+v authority=%+v",
					current.State.ManagedRuntimeTarget, authorityLog.committed)
			}
		})
	}
}

func TestManagedCanaryPreparedAtRoundTripsBeforeDesiredEffect(t *testing.T) {
	fixture := newManagedUpdateSeatOutcomeFixture(t)
	state := fixture.canary.State
	state.Stage = StagePreparedDesired
	preparedAt := state.ManagedRuntimeTarget.PreparedAt
	encoded, err := json.Marshal(state, json.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var restored MemberState
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !restored.ManagedRuntimeTarget.PreparedAt.Equal(preparedAt) ||
		!restored.ManagedRuntimeTarget.PreparedAt.Equal(fixture.preparedAt) || restored.Stage != StagePreparedDesired {
		t.Fatalf("prepared canary timestamp or pre-effect stage changed in state round trip: %+v", restored)
	}

	if _, err := fixture.controller.persist(t.Context(), 1, fixture.canary.Revision, restored); err != nil {
		t.Fatalf("persist prepared canary state = %v", err)
	}
	current := fixture.store.members[state.MemberID]
	if current.State.Stage != StagePreparedDesired || current.State.ManagedRuntimeTarget.Phase != ManagedUpdateSeatPrepared ||
		!current.State.ManagedRuntimeTarget.PreparedAt.Equal(preparedAt) {
		t.Fatalf("persisted pre-effect canary state changed deadline: %+v", current.State)
	}
}

func TestManagedCanaryHeldSeatCannotAdvanceFromLateProof(t *testing.T) {
	fixture := newManagedUpdateSeatOutcomeFixture(t)
	update, authorityLog := managedUpdateHistoryForFixture(t, &fixture, "", "")
	controller := managedCanaryServingController(t, fixture, update, authorityLog)
	state := fixture.canary.State
	state.ManagedRuntimeTarget.Phase = ManagedUpdateSeatHeld
	state.ManagedRuntimeTarget.Outcome = "candidate-proof-timeout"
	fixture.canary = VersionedMemberState{State: state, Revision: fixture.canary.Revision}
	fixture.store.members[state.MemberID] = fixture.canary
	instances, err := controller.fleet.Observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := controller.hosts.ListHosts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var instance oci.Instance
	for _, observed := range instances {
		if observed.ID == state.InstanceID {
			instance = observed
			break
		}
	}
	var status host.HostStatus
	for _, observed := range statuses {
		if observed.Registration.Node == state.HostNode {
			status = observed
			break
		}
	}
	if instance.ID == "" || status.Registration.Node == "" ||
		!controller.hasServingReport(fixture.intent, state, instance, status) {
		t.Fatal("late candidate serving report was not valid for the held seat")
	}
	// A report from a slow host reconcile still counts; one older than the
	// serving report bound does not.
	for _, test := range []struct {
		age   time.Duration
		valid bool
	}{{45 * time.Second, true}, {host.ReportMaxAge + 5*time.Second, false}} {
		aged := status
		aged.Reports = slices.Clone(status.Reports)
		for index := range aged.Reports {
			aged.Reports[index].ObservedAt = time.Now().Add(-test.age)
		}
		if controller.hasServingReport(fixture.intent, state, instance, aged) != test.valid {
			t.Fatalf("serving report aged %s: valid=%t, want %t", test.age, !test.valid, test.valid)
		}
	}
	before := fixture.store.casCalls

	acted, err := controller.advanceMember(t.Context(), 1, fixture.intent,
		Seat{MemberID: state.MemberID, Region: state.Region, FailureDomain: state.FailureDomain, Kind: state.Kind},
		fixture.canary, map[string]oci.Instance{instance.ID: instance}, map[string]host.HostStatus{status.Registration.Node: status})
	current := fixture.store.members[state.MemberID]
	if err != nil || acted || fixture.store.casCalls != before || current.State.ManagedRuntimeTarget.Phase != ManagedUpdateSeatHeld ||
		current.State.ManagedRuntimeTarget.Outcome != "candidate-proof-timeout" {
		t.Fatalf("late proof advanced a durably held canary: acted=%v err=%v state=%+v", acted, err, current.State)
	}
}

type managedUpdateSeatOutcomeFixture struct {
	intent           Intent
	update           ManagedUpdateIntent
	prepared         authority.ManagedUpdateRecord
	preparedSequence uint64
	preparedAt       time.Time
	canary           VersionedMemberState
	peer             VersionedMemberState
	store            *placementMemoryStore
	controller       *Controller
}

func newManagedUpdateSeatOutcomeFixture(t *testing.T) managedUpdateSeatOutcomeFixture {
	t.Helper()
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	canarySeat := Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}
	peerSeat := Seat{MemberID: elasticMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic}
	canaryState := testMemberState(t, intent, canarySeat, StageAwaitingHealthy)
	peerState := testMemberState(t, intent, peerSeat, StageServing)
	canaryState.InstanceID = "ocid1.instance.oc1..instance-a"
	canaryState.VolumeID = "ocid1.volume.oc1..volume-a"
	canaryState.AttachmentID = "ocid1.volumeattachment.oc1..attachment-a"
	peerState.InstanceID = "ocid1.instance.oc1..instance-b"
	peerState.VolumeID = "ocid1.volume.oc1..volume-b"
	peerState.AttachmentID = "ocid1.volumeattachment.oc1..attachment-b"
	peerState.AttachmentDevice = "/dev/sdc"
	peerState.AttachmentETag = "attachment-etag-b"
	preparedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	requestDigest := strings.Repeat("9", 64)
	canaryState.SchemaVersion = managedUpdateMemberStateSchemaVersion
	canaryState.ManagedRuntimeTarget = ManagedRuntimeTarget{
		OperationID: "0000000000E44GT0K557ASV7P0", AuthoritySequence: 41, RequestSHA256: requestDigest,
		PreparedAt: preparedAt, PlacementGeneration: intent.Generation,
		PlacementPayloadDigest: intent.PayloadDigest(), CanarySeatID: canaryState.MemberID,
		PreviousDesiredGeneration: canaryState.DesiredGeneration,
		PreviousArtifactDigest:    canaryState.RuntimeManifest.ArtifactDigest,
		DesiredGeneration:         canaryState.DesiredGeneration + 1,
		ArtifactDigest:            strings.Repeat("f", 64), ManifestDigest: strings.Repeat("1", 64),
		SourceDigest: strings.Repeat("2", 64), Phase: ManagedUpdateSeatPrepared,
	}
	canaryState.DesiredGeneration = canaryState.ManagedRuntimeTarget.DesiredGeneration
	canaryState.UpdatedAt = preparedAt.Add(time.Second)
	canaryState.OperationID = "000000000017GVSFVBERDYJFKX"
	canaryPredecessor := canaryState
	canaryPredecessor.ManagedRuntimeTarget = ManagedRuntimeTarget{}
	canaryPredecessor.DesiredGeneration = canaryState.ManagedRuntimeTarget.PreviousDesiredGeneration
	canary := VersionedMemberState{State: canaryState, Revision: 7}
	peer := VersionedMemberState{State: peerState, Revision: 4}
	update := ManagedUpdateIntent{
		DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
		PlacementGeneration: intent.Generation, PlacementPayloadDigest: intent.PayloadDigest(),
		CanarySeatID: canaryState.MemberID, CanaryDesiredGeneration: canaryState.ManagedRuntimeTarget.DesiredGeneration,
		OldArtifactDigest:       canaryState.RuntimeManifest.ArtifactDigest,
		CandidateArtifactDigest: canaryState.ManagedRuntimeTarget.ArtifactDigest,
		CandidateManifestDigest: canaryState.ManagedRuntimeTarget.ManifestDigest,
		CandidateSourceDigest:   canaryState.ManagedRuntimeTarget.SourceDigest,
		OperationID:             canaryState.ManagedRuntimeTarget.OperationID,
		Seats:                   []ManagedUpdateSeat{managedUpdateSeatFromState(canaryPredecessor), managedUpdateSeatFromState(peerState)},
	}
	prepared := authority.ManagedUpdateRecord{
		OperationID: update.OperationID, SignedRequestSHA256: requestDigest,
	}
	store := &placementMemoryStore{intents: []Intent{intent}, members: map[string]VersionedMemberState{
		canaryState.MemberID: canary, peerState.MemberID: peer,
	}}
	controller := &Controller{config: Config{Cell: "gru", Region: oci.RegionGRU,
		FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"}, ManagedOwner: "owner-a",
		FleetGeneration: 1, ImageID: "ocid1.image.oc1..placement-test",
		Environment: "production", MemberRole: "terrabase",
		Resources: Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 32 << 30}},
		store: store, fencer: placementTestFencer{}}
	return managedUpdateSeatOutcomeFixture{
		intent: intent, update: update, prepared: prepared, preparedSequence: 41, preparedAt: preparedAt,
		canary: canary, peer: peer, store: store, controller: controller,
	}
}

type managedUpdateTestAuthority struct {
	placementTestFencer
	placement      authority.LogEntry
	prepared       authority.LogEntry
	latest         authority.LogEntry
	history        []authority.LogEntry
	preparedRecord authority.ManagedUpdateRecord
	committed      authority.ManagedUpdateRecord
	nextSequence   uint64
}

func managedUpdateHistoryForFixture(t *testing.T, fixture *managedUpdateSeatOutcomeFixture,
	terminalPhase authority.ManagedUpdatePhase, outcome string,
) (ManagedUpdateIntent, *managedUpdateTestAuthority) {
	t.Helper()
	update := validManagedUpdateIntent(t)
	update.Cell = fixture.controller.config.Cell
	update.DatabaseID = fixture.intent.DatabaseID
	update.PartitionID = fixture.intent.PartitionID
	update.PlacementGeneration = fixture.intent.Generation
	update.PlacementPayloadDigest = fixture.intent.PayloadDigest()
	update.PlacementSequence = 18
	update.AuthorityEpoch = 1
	update.OperationID = fixture.canary.State.ManagedRuntimeTarget.OperationID
	update.Role = fixture.controller.config.MemberRole
	update.Environment = fixture.controller.config.Environment
	update.OldArtifactDigest = fixture.canary.State.RuntimeManifest.ArtifactDigest
	update.CandidateArtifactDigest = fixture.canary.State.ManagedRuntimeTarget.ArtifactDigest
	update.CandidateManifestDigest = fixture.canary.State.ManagedRuntimeTarget.ManifestDigest
	update.CandidateSourceDigest = fixture.canary.State.ManagedRuntimeTarget.SourceDigest
	update.CanarySeatID = fixture.canary.State.MemberID
	update.CanaryDesiredGeneration = fixture.canary.State.ManagedRuntimeTarget.DesiredGeneration
	canaryPredecessor := fixture.canary.State
	canaryPredecessor.ManagedRuntimeTarget = ManagedRuntimeTarget{}
	canaryPredecessor.DesiredGeneration = fixture.canary.State.ManagedRuntimeTarget.PreviousDesiredGeneration
	update.Seats = []ManagedUpdateSeat{
		managedUpdateSeatFromState(canaryPredecessor), managedUpdateSeatFromState(fixture.peer.State),
	}
	slices.SortFunc(update.Seats, func(left, right ManagedUpdateSeat) int {
		return strings.Compare(left.SeatID, right.SeatID)
	})
	update.DurabilityProfile = ManagedUpdateDurabilityProfile{
		SchemaVersion: ManagedUpdateSchemaVersion, Region: fixture.canary.State.Region,
		SQLSchemaBundleSHA256: fixture.canary.State.RuntimeManifest.SQLSchemaBundleSHA256,
		LiveS3ConfigSHA256:    fixture.canary.State.RuntimeManifest.LiveS3ConfigSHA256,
		LiveS3TargetSHA256:    fixture.canary.State.RuntimeManifest.LiveS3TargetSHA256,
		LiveS3Credential:      fixture.canary.State.RuntimeManifest.LiveS3Credential,
		Volumes: []ManagedUpdateVolumeProfile{
			{SeatID: fixture.canary.State.MemberID, VolumeID: fixture.canary.State.VolumeID,
				FileSystemUUID: fixture.canary.State.RuntimeManifest.FileSystemUUID,
				FileSystemType: fixture.canary.State.RuntimeManifest.FileSystemType},
			{SeatID: fixture.peer.State.MemberID, VolumeID: fixture.peer.State.VolumeID,
				FileSystemUUID: fixture.peer.State.RuntimeManifest.FileSystemUUID,
				FileSystemType: fixture.peer.State.RuntimeManifest.FileSystemType},
		},
	}
	slices.SortFunc(update.DurabilityProfile.Volumes, func(left, right ManagedUpdateVolumeProfile) int {
		return strings.Compare(left.SeatID, right.SeatID)
	})
	profileDigest, err := update.DurabilityProfile.Digest()
	if err != nil {
		t.Fatalf("DurabilityProfile.Digest() error = %v", err)
	}
	statement := ManagedCompatibilityEvidence{
		SchemaVersion: ManagedCompatibilitySchemaVersion, Cell: update.Cell,
		OperationID: update.OperationID, OldArtifactDigest: update.OldArtifactDigest,
		CandidateArtifactDigest: update.CandidateArtifactDigest,
		CandidateManifestDigest: update.CandidateManifestDigest,
		DurabilityProfileSHA256: profileDigest, MixedVersionReplicationSupported: true,
		ClientDataCompatibilitySupported: true, PersistentFormatReadSupported: true,
		PersistentFormatWriteSupported: true,
	}
	update.CompatibilityEvidence, _ = signedManagedCompatibility(t, update, statement)
	if err := update.Validate(); err != nil {
		t.Fatalf("managed history request Validate() error = %v", err)
	}
	requestPayload, err := protocol.EncodeJSON(update)
	if err != nil {
		t.Fatalf("EncodeJSON(update) error = %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(requestPayload, protocol.EnvelopeScope{
		Region: update.Cell, Kind: ManagedUpdateEnvelopeKind, Actor: "operator",
		OperationID: update.OperationID, Generation: update.CanaryDesiredGeneration, Epoch: update.AuthorityEpoch,
	}, now, now.Add(time.Hour), privateKey)
	if err != nil {
		t.Fatalf("SignEnvelope(update) error = %v", err)
	}
	signedRequest, err := protocol.EncodeJSON(envelope)
	if err != nil {
		t.Fatalf("EncodeJSON(envelope) error = %v", err)
	}
	requestDigest := sha256.Sum256(signedRequest)
	prepared := authority.ManagedUpdateRecord{
		SchemaVersion: 1, Cell: update.Cell, DatabaseID: update.DatabaseID,
		PartitionID: update.PartitionID, OperationID: update.OperationID,
		Phase: authority.ManagedUpdatePrepared, SignedRequest: signedRequest,
		SignedRequestSHA256:    hex.EncodeToString(requestDigest[:]),
		PlacementGeneration:    update.PlacementGeneration,
		PlacementPayloadDigest: update.PlacementPayloadDigest,
		PlacementSequence:      update.PlacementSequence, CanarySeatID: update.CanarySeatID,
		CanaryDesiredGeneration: update.CanaryDesiredGeneration,
		OldArtifactDigest:       update.OldArtifactDigest,
		CandidateArtifactDigest: update.CandidateArtifactDigest,
		CandidateManifestDigest: update.CandidateManifestDigest,
		CandidateSourceDigest:   update.CandidateSourceDigest,
		DurabilityProfileSHA256: profileDigest,
	}
	if err := prepared.Validate(); err != nil {
		t.Fatalf("prepared authority record Validate() error = %v", err)
	}
	fixture.canary.State.ManagedRuntimeTarget.RequestSHA256 = prepared.SignedRequestSHA256
	fixture.store.members[fixture.canary.State.MemberID] = fixture.canary
	preparedEntry := managedUpdateTestEntry(t, prepared, 41)
	entries := []authority.LogEntry{preparedEntry}
	latest := preparedEntry
	if terminalPhase != "" {
		terminal := prepared
		terminal.Phase, terminal.Outcome = terminalPhase, outcome
		terminalEntry := managedUpdateTestEntry(t, terminal, 42)
		entries = append(entries, terminalEntry)
		latest = terminalEntry
	}
	placementPayload, err := protocol.EncodeJSON(fixture.intent)
	if err != nil {
		t.Fatalf("EncodeJSON(placement) error = %v", err)
	}
	placement := authority.LogEntry{
		Kind:        authority.MutationPlacementIntent,
		SubjectKey:  fixture.intent.DatabaseID + "." + fixture.intent.PartitionID,
		OperationID: fixture.intent.OperationID(), Epoch: 1, Sequence: update.PlacementSequence,
		Payload: placementPayload,
	}
	return update, &managedUpdateTestAuthority{
		placement: placement, prepared: preparedEntry, latest: latest, history: entries,
		preparedRecord: prepared, nextSequence: 43,
	}
}

func managedUpdateTestEntry(t *testing.T, record authority.ManagedUpdateRecord, sequence uint64) authority.LogEntry {
	t.Helper()
	payload, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal(managed update record) error = %v", err)
	}
	return authority.LogEntry{
		Kind:        authority.MutationManagedUpdate,
		SubjectKey:  record.DatabaseID + "." + record.PartitionID + "." + record.OperationID + "." + string(record.Phase),
		OperationID: record.OperationID, Epoch: 1, Sequence: sequence, Payload: payload,
	}
}

func (authorityLog *managedUpdateTestAuthority) ReadManagedUpdate(_ context.Context,
	databaseID, partitionID string,
) (authority.LogEntry, error) {
	if authorityLog.latest.OperationID == "" ||
		!strings.HasPrefix(authorityLog.latest.SubjectKey, databaseID+"."+partitionID+".") {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	return authorityLog.latest, nil
}

func (authorityLog *managedUpdateTestAuthority) ReadManagedUpdateOperation(_ context.Context,
	databaseID, partitionID, operationID string,
) ([]authority.LogEntry, error) {
	if len(authorityLog.history) == 0 || authorityLog.prepared.OperationID != operationID ||
		authorityLog.prepared.SubjectKey != databaseID+"."+partitionID+"."+operationID+".prepared" {
		return nil, authority.ErrNotFound
	}
	return slices.Clone(authorityLog.history), nil
}

func (authorityLog *managedUpdateTestAuthority) ListManagedUpdates(context.Context,
	string, string,
) ([]authority.LogEntry, error) {
	return slices.Clone(authorityLog.history), nil
}

func (authorityLog *managedUpdateTestAuthority) ReadPlacementIntent(_ context.Context,
	databaseID, partitionID string,
) (authority.LogEntry, error) {
	if authorityLog.placement.SubjectKey != databaseID+"."+partitionID {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	return authorityLog.placement, nil
}

func (authorityLog *managedUpdateTestAuthority) CommitManagedUpdate(ctx context.Context,
	_ uint64, record authority.ManagedUpdateRecord, expectedSequence uint64,
	verify func(context.Context) error,
) (uint64, error) {
	if expectedSequence != authorityLog.prepared.Sequence {
		return 0, authority.ErrInvalidTransition
	}
	if verify != nil {
		if err := verify(ctx); err != nil {
			return 0, err
		}
	}
	authorityLog.committed = record
	return authorityLog.nextSequence, nil
}

func managedCanaryServingController(t *testing.T, fixture managedUpdateSeatOutcomeFixture,
	update ManagedUpdateIntent, authorityLog *managedUpdateTestAuthority,
) *Controller {
	t.Helper()
	controller := &Controller{
		config: fixture.controller.config, store: fixture.store, fencer: authorityLog,
		resolveArtifact: func(context.Context, string, string, string) (AdmittedArtifact, error) {
			return AdmittedArtifact{Digest: update.CandidateArtifactDigest,
				ManifestDigest: update.CandidateManifestDigest, SourceDigest: update.CandidateSourceDigest}, nil
		},
	}
	instances := attachedInstances(t, fixture.intent)
	stateByNode := map[string]MemberState{
		fixture.canary.State.HostNode: fixture.canary.State,
		fixture.peer.State.HostNode:   fixture.peer.State,
	}
	for instanceIndex := range instances {
		instance := &instances[instanceIndex]
		state := stateByNode[instance.Node]
		instance.ID = state.InstanceID
		instance.CreateKey = state.CreateKey
		for attachmentIndex := range instance.Attachments {
			attachment := &instance.Attachments[attachmentIndex]
			attachment.ID = state.AttachmentID
			attachment.VolumeID = state.VolumeID
			attachment.InstanceID = state.InstanceID
			attachment.ETag = state.AttachmentETag
			attachment.Device = state.AttachmentDevice
			attachment.IsPvEncryptionInTransitEnabled = true
		}
	}
	statuses := admittedStatuses(t, fixture.intent)
	statusByMember := make(map[string]int, len(statuses))
	for index := range statuses {
		for memberID, state := range stateByNode {
			if state.HostNode == statuses[index].Registration.Node {
				statusByMember[memberID] = index
				managedOCI := *statuses[index].Registration.ManagedOCI
				managedOCI.InstanceID = state.InstanceID
				statuses[index].Registration.ManagedOCI = &managedOCI
				break
			}
		}
	}
	fleet := &placementTestFleet{instances: instances}
	hosts := &placementTestHosts{statuses: statuses}
	controller.fleet, controller.hosts = fleet, hosts

	seats, err := controller.localSeats(fixture.intent)
	if err != nil {
		t.Fatalf("localSeats() error = %v", err)
	}
	for _, seat := range seats {
		state := fixture.store.members[seat.MemberID].State
		want, err := controller.memberDesired(1, fixture.intent, state, seat)
		if err != nil {
			t.Fatalf("memberDesired(%s) error = %v", seat.MemberID, err)
		}
		hosts.desired = append(hosts.desired, want)
		statusIndex, exists := statusByMember[state.HostNode]
		if !exists {
			t.Fatalf("no admitted host status for %s", state.HostNode)
		}
		statuses[statusIndex].Reports = []host.Report{managedCanaryServingReport(t, controller, fixture.intent,
			state, statuses[statusIndex])}
	}
	hosts.statuses = statuses
	return controller
}

func managedCanaryServingReport(t *testing.T, controller *Controller, intent Intent,
	state MemberState, status host.HostStatus,
) host.Report {
	t.Helper()
	manifest := state.EffectiveRuntimeManifest()
	member := controller.memberBinding(intent, state)
	var survivor memberstatus.Survivor
	for _, row := range intent.CanonicalRoster.Rows {
		if row.MemberID == manifest.ReplicationPeerMemberID && row.MemberID != state.CanonicalRosterRow.MemberID {
			survivor = memberstatus.Survivor{MemberID: row.MemberID, Incarnation: row.Incarnation}
			break
		}
	}
	if survivor.MemberID == "" {
		t.Fatal("test fixture has no replication survivor")
	}
	mountPath, err := host.ManagedMountPath(manifest.ManagedRuntimeRoot, member)
	if err != nil {
		t.Fatalf("ManagedMountPath() error = %v", err)
	}
	process := memberstatus.Process{PID: 1234, StartNonce: "00000000000064eeb57eb73c4a8035be"}
	authorityBinding := memberstatus.Authority{
		Epoch: state.AuthorityReference.Epoch, ConfigurationID: state.AuthorityReference.ConfigurationID,
		CertificateSHA256: state.AuthorityReference.CertificateSHA256,
		TLSLeafSHA256:     state.CanonicalRosterRow.TLSLeafSHA256,
	}
	proof := memberstatus.ServingProof{
		SchemaVersion: 1, Nonce: strings.Repeat("1", 32), Process: process,
		Scope: memberstatus.Scope{
			ClusterID: intent.CanonicalRoster.ClusterID, TenantID: intent.CanonicalRoster.TenantID,
			DatabaseID: intent.CanonicalRoster.DatabaseID, ShardID: intent.CanonicalRoster.ShardID,
			MemberID: state.CanonicalRosterRow.MemberID, Incarnation: state.CanonicalRosterRow.Incarnation,
		},
		Authority: authorityBinding, Serving: true,
		Listeners: memberstatus.Listeners{Client: true, Replication: true},
		Object: memberstatus.ObjectProof{
			RootSHA256: strings.Repeat("3", 64), TargetSHA256: strings.Repeat("4", 64),
			InboxArchiveSHA256AtRecovery: strings.Repeat("5", 64), LocalSourceSequence: 12,
			RemoteInboxDurableSequence: 9, RemoteAppliedSequence: 9,
		},
		Replication: memberstatus.ReplicationProof{
			LocalSourceSequence: 12, PeerMemberID: survivor.MemberID, PeerIncarnation: survivor.Incarnation,
			CurrentAuthenticated: true, PeerDurableSequence: 12, PeerAppliedSequence: 12,
			LocalInboxDurableSequence: 9, LocalInboxAppliedSequence: 9,
		},
	}
	attachment, ok := observedAttachment(oci.Instance{Attachments: []oci.Attachment{{
		ID: state.AttachmentID, VolumeID: state.VolumeID, InstanceID: state.InstanceID,
		ETag: state.AttachmentETag, Device: state.AttachmentDevice, State: "ATTACHED",
		IsPvEncryptionInTransitEnabled: true,
	}}}, state)
	if !ok {
		t.Fatal("test fixture has no observed attachment")
	}
	return host.Report{
		Cell: controller.config.Cell, Node: status.Registration.Node,
		Environment: controller.config.Environment, Role: controller.config.MemberRole,
		Digest: manifest.ArtifactDigest, Generation: state.DesiredGeneration,
		State: "running", ObservedAt: time.Now().UTC(),
		Managed: &host.ManagedRuntimeReport{
			Member: member,
			Authority: host.MemberAuthority{
				Epoch: authorityBinding.Epoch, ConfigurationID: authorityBinding.ConfigurationID,
				CertificateSHA256: authorityBinding.CertificateSHA256,
				TLSLeafSHA256:     authorityBinding.TLSLeafSHA256,
			},
			OCI:      *status.Registration.ManagedOCI,
			VolumeID: state.VolumeID, AttachmentID: state.AttachmentID, AttachmentETag: attachment.ETag,
			FileSystemUUID: manifest.FileSystemUUID, FileSystemType: manifest.FileSystemType,
			MountDevice: state.AttachmentDevice, MountPath: mountPath, MountID: 23,
			ProcessPID: process.PID, ProcessStart: "12345", ProcessCgroup: "/terrabase",
			ProcessBootID: process.StartNonce, StorageRecovered: true, ListenerReady: true,
			ServingProof: &proof,
		},
	}
}

func managedUpdateSeatFromState(state MemberState) ManagedUpdateSeat {
	return ManagedUpdateSeatFor(state, "owner-a", 1)
}

func validManagedUpdateIntent(t *testing.T) ManagedUpdateIntent {
	t.Helper()

	profile := ManagedUpdateDurabilityProfile{
		SchemaVersion: ManagedUpdateSchemaVersion,
		Region:        oci.RegionGRU,
		Volumes: []ManagedUpdateVolumeProfile{
			{SeatID: "0000000000XG8SBD7XGE97V28G", VolumeID: "ocid1.volume.oc1..volume-a", FileSystemUUID: "123e4567-e89b-12d3-a456-426614174000", FileSystemType: "ext4"},
			{SeatID: "000000000082AXF7GZQT1D126Y", VolumeID: "ocid1.volume.oc1..volume-b", FileSystemUUID: "123e4567-e89b-12d3-a456-426614174001", FileSystemType: "xfs"},
		},
		SQLSchemaBundleSHA256: strings.Repeat("a", 64),
		LiveS3ConfigSHA256:    strings.Repeat("b", 64),
		LiveS3TargetSHA256:    strings.Repeat("c", 64),
		LiveS3Credential:      oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1..secret-a", VersionNumber: 1},
	}
	slices.SortFunc(profile.Volumes, func(a, b ManagedUpdateVolumeProfile) int { return strings.Compare(a.SeatID, b.SeatID) })
	profileDigest, err := profile.Digest()
	if err != nil {
		t.Fatalf("profile.Digest() error = %v", err)
	}

	intent := ManagedUpdateIntent{
		SchemaVersion:           ManagedUpdateSchemaVersion,
		Cell:                    "gru",
		DatabaseID:              "0000000000WVSMBJNMAWCDJBSK",
		PartitionID:             "0000000000Z3WK359G2W66CVT8",
		PlacementGeneration:     7,
		PlacementPayloadDigest:  strings.Repeat("d", 64),
		PlacementSequence:       18,
		AuthorityEpoch:          9,
		OperationID:             "00000000000NV7A9CE3MES6S1F",
		Role:                    "terrabase",
		Environment:             "production",
		OldArtifactDigest:       strings.Repeat("e", 64),
		CandidateArtifactDigest: strings.Repeat("f", 64),
		CandidateManifestDigest: strings.Repeat("1", 64),
		CandidateSourceDigest:   strings.Repeat("2", 64),
		CanarySeatID:            "0000000000XG8SBD7XGE97V28G",
		CanaryDesiredGeneration: 5,
		DurabilityProfile:       profile,
		Seats: []ManagedUpdateSeat{
			{SeatID: "0000000000XG8SBD7XGE97V28G", Region: oci.RegionGRU, MemberID: "0J7S2PFT4V2B9T8NJ2CRA1EG00", Incarnation: "33333333333333333333333333333333", TLSLeafSHA256: strings.Repeat("4", 64), RuntimeManifestDigest: strings.Repeat("5", 64), HostNode: "node-a", HostGeneration: 2, HostAttempt: 1, OCIInstanceID: "ocid1.instance.oc1..instance-a", OCIOwner: "owner-a", OCIFleetGeneration: 3, CreateKey: "0000000000R58Y74PAABAQ7X2V", VolumeID: "ocid1.volume.oc1..volume-a", AttachmentID: "ocid1.volumeattachment.oc1..attachment-a", AttachmentETag: "attachment-etag-a", AttachmentDevice: "/dev/oracleoci/oraclevda", DesiredGeneration: 4, ArtifactDigest: strings.Repeat("e", 64)},
			{SeatID: "000000000082AXF7GZQT1D126Y", Region: oci.RegionGRU, MemberID: "0J7S2PFT4V2B9T8NJ2CRA1EG01", Incarnation: "000000000000e955f3ff88e731e6c0a9", TLSLeafSHA256: strings.Repeat("7", 64), RuntimeManifestDigest: strings.Repeat("8", 64), HostNode: "node-b", HostGeneration: 4, HostAttempt: 1, OCIInstanceID: "ocid1.instance.oc1..instance-b", OCIOwner: "owner-a", OCIFleetGeneration: 3, CreateKey: "0000000000GTA7T55FAST9ZNW4", VolumeID: "ocid1.volume.oc1..volume-b", AttachmentID: "ocid1.volumeattachment.oc1..attachment-b", AttachmentETag: "attachment-etag-b", AttachmentDevice: "/dev/oracleoci/oraclevdb", DesiredGeneration: 8, ArtifactDigest: strings.Repeat("e", 64)},
		},
	}
	slices.SortFunc(intent.Seats, func(a, b ManagedUpdateSeat) int { return strings.Compare(a.SeatID, b.SeatID) })
	statement := ManagedCompatibilityEvidence{
		SchemaVersion:                    ManagedCompatibilitySchemaVersion,
		Cell:                             intent.Cell,
		OperationID:                      intent.OperationID,
		OldArtifactDigest:                intent.OldArtifactDigest,
		CandidateArtifactDigest:          intent.CandidateArtifactDigest,
		CandidateManifestDigest:          intent.CandidateManifestDigest,
		DurabilityProfileSHA256:          profileDigest,
		MixedVersionReplicationSupported: true,
		ClientDataCompatibilitySupported: true,
		PersistentFormatReadSupported:    true,
		PersistentFormatWriteSupported:   true,
	}
	intent.CompatibilityEvidence, _ = signedManagedCompatibility(t, intent, statement)
	return intent
}

func signedManagedCompatibility(t *testing.T, intent ManagedUpdateIntent, evidence ManagedCompatibilityEvidence) (protocol.Envelope, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	payload, err := protocol.EncodeJSON(evidence)
	if err != nil {
		t.Fatalf("EncodeJSON() error = %v", err)
	}
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: intent.Cell, Kind: ManagedCompatibilityEnvelopeKind, Actor: "compatibility-authority",
		OperationID: intent.OperationID, Generation: intent.CanaryDesiredGeneration, Epoch: 8,
	}, now, now.Add(time.Minute), privateKey)
	if err != nil {
		t.Fatalf("SignEnvelope() error = %v", err)
	}
	return envelope, publicKey
}

func resignManagedCompatibility(t *testing.T, intent ManagedUpdateIntent, mutate func(*ManagedCompatibilityEvidence)) protocol.Envelope {
	t.Helper()
	evidence, err := decodeManagedCompatibility(intent.CompatibilityEvidence)
	if err != nil {
		t.Fatalf("decodeManagedCompatibility() error = %v", err)
	}
	mutate(&evidence)
	envelope, _ := signedManagedCompatibility(t, intent, evidence)
	return envelope
}

func decodeManagedCompatibility(envelope protocol.Envelope) (ManagedCompatibilityEvidence, error) {
	var evidence ManagedCompatibilityEvidence
	if err := protocol.DecodeStrict(envelope.Payload, &evidence, protocol.MaxPayloadBytes); err != nil {
		return ManagedCompatibilityEvidence{}, err
	}
	return evidence, nil
}
