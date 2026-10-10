package placement

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestControllerHoldsAfterAttachedVolumeWithoutObservedDevice(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := newPlacementMemoryStore(t, intent)
	fleet := &placementTestFleet{instances: attachedInstances(t, intent)}
	hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, hosts, func(reason string) { holds = append(holds, reason) })

	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, member := range store.members {
		if member.State.Stage != StageAwaitingRuntimeContract {
			t.Fatalf("member advanced beyond the runtime hold: %#v", member.State)
		}
	}
	if fleet.ensureCalls != 0 || fleet.volumeCalls != 0 || fleet.attachCalls != 0 || fleet.cordonCalls != 0 || fleet.terminateCalls != 0 {
		t.Fatalf("attached runtime hold performed OCI mutations: %#v", fleet)
	}
	if hosts.desiredWrites != 0 {
		t.Fatalf("runtime hold wrote host desired state %d times", hosts.desiredWrites)
	}
	if len(holds) != 2 {
		t.Fatalf("hold callbacks = %d, want one per member", len(holds))
	}
}

func TestControllerHoldsUnsupportedMultiRegionSenderBeforeAnyEffect(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU, oci.RegionSFO))
	store := &placementMemoryStore{intents: []Intent{intent}, members: make(map[string]VersionedMemberState)}
	fleet := &placementTestFleet{}
	hosts := &placementTestHosts{}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, hosts, func(reason string) { holds = append(holds, reason) })
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(holds) != 1 || !strings.Contains(holds[0], "exactly two members in one region") ||
		store.casCalls != 0 || fleet.ensureCalls != 0 || fleet.volumeCalls != 0 || fleet.attachCalls != 0 || hosts.desiredWrites != 0 {
		t.Fatalf("unsupported runtime caused an effect or unclear hold: holds=%q CAS=%d fleet=%+v desired=%d", holds, store.casCalls, fleet, hosts.desiredWrites)
	}
}

func TestControllerAppliesOnlyPreparedObservedManagedDesired(t *testing.T) {
	draft := validIntent(oci.RegionGRU)
	draft.RuntimeManifests[0].SQLSchemaBundleSHA256 = strings.Repeat("b", 64)
	intent := committedTestIntent(t, draft)
	store := newPlacementMemoryStore(t, intent)
	instances := attachedInstances(t, intent)
	for index := range instances {
		instances[index].Attachments[0].Device = "/dev/oracleoci/oraclevdb"
		instances[index].Attachments[0].IsPvEncryptionInTransitEnabled = true
	}
	fleet := &placementTestFleet{instances: instances}
	hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
	controller := startTestPlacementController(t, store, fleet, hosts, nil)
	seatID := permanentMember(oci.RegionGRU)
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	prepared := store.members[seatID].State
	if prepared.Stage != StagePreparedDesired || prepared.AttachmentDevice != "/dev/oracleoci/oraclevdb" ||
		prepared.AttachmentETag != "attachment-etag" || hosts.desiredWrites != 0 {
		t.Fatalf("attached member was not durably prepared before desired effect: %+v writes=%d", prepared, hosts.desiredWrites)
	}
	// Reconstructing the controller must replay the same durable prepared pins.
	controller = startTestPlacementController(t, store, fleet, hosts, nil)
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if hosts.desiredWrites != 1 || store.members[seatID].State.Stage != StageAwaitingHealthy {
		t.Fatalf("prepared desired was not applied and held for serving proof: writes=%d state=%+v", hosts.desiredWrites, store.members[seatID].State)
	}
	desired := hosts.desired[0]
	if desired.ManagedMember == nil || desired.ManagedMember.Runtime == nil ||
		desired.AuthorityEpoch != 1 || desired.ManagedMember.Authority.Epoch != 7 ||
		desired.ManagedMember.Runtime.DevicePath != prepared.AttachmentDevice ||
		desired.ManagedMember.Runtime.SQLSchemaBundleSHA256 != prepared.RuntimeManifest.SQLSchemaBundleSHA256 ||
		desired.ManagedMember.AttachmentETag != prepared.AttachmentETag ||
		desired.ManagedMember.SourceDigest != prepared.RuntimeManifest.SourceDigest ||
		desired.Digest != prepared.RuntimeManifest.ArtifactDigest {
		t.Fatalf("applied desired lost signed or observed pins: %+v", desired)
	}
	mount, err := host.ManagedMountPath(prepared.RuntimeManifest.ManagedRuntimeRoot, desired.ManagedMember.Member)
	if err != nil || desired.ManagedMember.Runtime.MountPath != mount {
		t.Fatalf("managed mount path = %q, %v; want %q", desired.ManagedMember.Runtime.MountPath, err, mount)
	}
}

func TestControllerWithholdsPreparedDesiredWhenFreshInputsChange(t *testing.T) {
	for _, test := range []struct {
		name     string
		freshOCI bool
		change   func(*placementTestFleet, *placementTestHosts)
	}{
		{"attachment device", true, func(f *placementTestFleet, _ *placementTestHosts) {
			f.instances[0].Attachments[0].Device = "/dev/sdc"
		}},
		{"attachment ETag", true, func(f *placementTestFleet, _ *placementTestHosts) {
			f.instances[0].Attachments[0].ETag = "changed"
		}},
		{"host session", false, func(_ *placementTestFleet, h *placementTestHosts) {
			h.statuses[0].SessionExpiresAt = time.Now().Add(-time.Second)
		}},
		{"host desired target", false, func(_ *placementTestFleet, h *placementTestHosts) {
			h.desired = []host.Desired{{Cell: "gru", Node: "node-" + strings.ToLower(permanentMember(oci.RegionGRU)), Role: "terrabase", Digest: "different"}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			intent := committedTestIntent(t, validIntent(oci.RegionGRU))
			store := newPlacementMemoryStore(t, intent)
			instances := attachedInstances(t, intent)
			for index := range instances {
				instances[index].Attachments[0].Device = "/dev/sdb"
				instances[index].Attachments[0].IsPvEncryptionInTransitEnabled = true
			}
			fleet := &placementTestFleet{instances: instances}
			hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
			controller := startTestPlacementController(t, store, fleet, hosts, nil)
			if err := controller.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
			if store.members[permanentMember(oci.RegionGRU)].State.Stage != StagePreparedDesired {
				t.Fatal("member did not reach prepared desired")
			}
			if test.freshOCI {
				observations := 0
				fleet.onObserve = func() {
					observations++
					if observations == 2 {
						test.change(fleet, hosts)
					}
				}
			} else if test.name == "host session" {
				reads := 0
				hosts.onListHosts = func() {
					reads++
					if reads == 2 {
						test.change(fleet, hosts)
					}
				}
			} else {
				test.change(fleet, hosts)
			}
			if err := controller.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
			if hosts.desiredWrites != 0 || store.members[permanentMember(oci.RegionGRU)].State.Stage != StagePreparedDesired {
				t.Fatalf("changed evidence applied desired: writes=%d state=%+v", hosts.desiredWrites, store.members[permanentMember(oci.RegionGRU)].State)
			}
		})
	}
}

// Before desired state, the member's freshly observed host must still be the
// bound one; only then does its own image qualify the write.
func TestControllerPreparedDesiredValidatesTheObservedHost(t *testing.T) {
	for name, change := range map[string]func(*oci.Instance){
		"unchanged":        nil,
		"owner":            func(instance *oci.Instance) { instance.Owner = "0000000000V4MRM46HP1SNGDYW" },
		"fleet generation": func(instance *oci.Instance) { instance.Generation++ },
		"boot descriptor":  func(instance *oci.Instance) { instance.BootDescriptorSHA256 = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			intent := committedTestIntent(t, validIntent(oci.RegionGRU))
			store := newPlacementMemoryStore(t, intent)
			instances := attachedInstances(t, intent)
			for index := range instances {
				instances[index].Attachments[0].Device = "/dev/sdb"
				instances[index].Attachments[0].IsPvEncryptionInTransitEnabled = true
			}
			fleet := &placementTestFleet{instances: instances}
			hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
			controller := startTestPlacementController(t, store, fleet, hosts, nil)
			if err := controller.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
			if store.members[permanentMember(oci.RegionGRU)].State.Stage != StagePreparedDesired {
				t.Fatal("member did not reach prepared desired")
			}
			fleet.verifiedImages = nil
			if change == nil {
				if err := controller.Tick(t.Context()); err != nil || hosts.desiredWrites == 0 ||
					!slices.Contains(fleet.verifiedImages, fleet.instances[0].ImageID) {
					t.Fatalf("bound host: err=%v writes=%d verified=%v", err, hosts.desiredWrites, fleet.verifiedImages)
				}
				return
			}
			change(&fleet.instances[0])
			if err := controller.Tick(t.Context()); err != nil || hosts.desiredWrites != 0 ||
				store.members[permanentMember(oci.RegionGRU)].State.Stage != StagePreparedDesired {
				t.Fatalf("changed host: err=%v writes=%d", err, hosts.desiredWrites)
			}
		})
	}
}

func TestControllerHoldsUnadmittedRuntimeAndReplaysPreparedCASConflict(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := newPlacementMemoryStore(t, intent)
	instances := attachedInstances(t, intent)
	for index := range instances {
		instances[index].Attachments[0].Device = "/dev/sdb"
		instances[index].Attachments[0].IsPvEncryptionInTransitEnabled = true
	}
	fleet := &placementTestFleet{instances: instances}
	hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
	controller := startTestPlacementController(t, store, fleet, hosts, nil)
	controller.resolveArtifact = func(_ context.Context, digest, _, _ string) (AdmittedArtifact, error) {
		return AdmittedArtifact{Digest: digest, SourceDigest: strings.Repeat("f", 64)}, nil
	}
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	seatID := permanentMember(oci.RegionGRU)
	if store.members[seatID].State.Stage != StageAwaitingRuntimeContract || hosts.desiredWrites != 0 {
		t.Fatal("unadmitted source reached prepared desired")
	}
	controller = startTestPlacementController(t, store, fleet, hosts, nil)
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.members[seatID].State.Stage != StagePreparedDesired {
		t.Fatal("admitted runtime did not reach prepared desired")
	}
	store.onCAS = func(state MemberState) error {
		if state.Stage == StageAwaitingHealthy {
			store.onCAS = nil
			return ErrStoreConflict
		}
		return nil
	}
	if err := controller.Tick(t.Context()); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("post-effect CAS conflict = %v, want ErrStoreConflict", err)
	}
	if hosts.desiredWrites != 1 || store.members[seatID].State.Stage != StagePreparedDesired {
		t.Fatal("post-effect CAS conflict did not retain prepared replay")
	}
	controller = startTestPlacementController(t, store, fleet, hosts, nil)
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if hosts.desiredWrites != 2 || store.members[seatID].State.Stage != StageAwaitingHealthy ||
		!reflect.DeepEqual(hosts.desired[0], hosts.desired[1]) {
		t.Fatalf("prepared replay changed desired target: writes=%d state=%+v", hosts.desiredWrites, store.members[seatID].State)
	}
}

func TestControllerRequiresCurrentArtifactAdmissionBeforeEveryManagedOCIEffect(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seatID := permanentMember(oci.RegionGRU)
	for _, stage := range []MemberStage{StagePreparedHost, StageAwaitingHost, StagePreparedVolume, StagePreparedAttach} {
		t.Run(string(stage), func(t *testing.T) {
			store := newPlacementMemoryStore(t, intent)
			member := store.members[seatID]
			member.State.Stage = stage
			if stage == StagePreparedHost || stage == StageAwaitingHost {
				member.State.HostGeneration = 0
			}
			if stage == StagePreparedVolume {
				member.State.VolumeID, member.State.AttachmentID = "", ""
			}
			store.members[seatID] = member
			instances := attachedInstances(t, intent)
			if stage == StageAwaitingHost {
				instances = nil
			}
			if stage == StagePreparedAttach {
				instances[0].Attachments = nil
			}
			fleet := &placementTestFleet{instances: instances}
			hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
			controller := startTestPlacementController(t, store, fleet, hosts, nil)
			controller.resolveArtifact = func(_ context.Context, digest, _, _ string) (AdmittedArtifact, error) {
				return AdmittedArtifact{Digest: digest, SourceDigest: strings.Repeat("f", 64)}, nil
			}
			if err := controller.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
			if fleet.ensureCalls != 0 || fleet.volumeCalls != 0 || fleet.attachCalls != 0 || hosts.desiredWrites != 0 {
				t.Fatalf("unadmitted artifact caused OCI or host effect: ensure=%d volume=%d attach=%d desired=%d",
					fleet.ensureCalls, fleet.volumeCalls, fleet.attachCalls, hosts.desiredWrites)
			}
		})
	}
}

func TestControllerRecoveredAttachmentRequiresCurrentArtifactAndImageQualification(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := newPlacementMemoryStore(t, intent)
	for memberID, member := range store.members {
		member.State.Stage = StagePreparedAttach
		store.members[memberID] = member
	}
	fleet := &placementTestFleet{instances: attachedInstances(t, intent), imageVerifyErr: oci.ErrImageNotQualified}
	hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
	controller := startTestPlacementController(t, store, fleet, hosts, nil)
	seatID := permanentMember(oci.RegionGRU)
	if err := controller.Tick(t.Context()); !errors.Is(err, oci.ErrImageNotQualified) ||
		store.casCalls != 0 || fleet.attachCalls != 0 || hosts.desiredWrites != 0 ||
		store.members[seatID].State.Stage != StagePreparedAttach {
		t.Fatalf("observed attachment bypassed image qualification: err=%v CAS=%d attach=%d desired=%d stage=%s",
			err, store.casCalls, fleet.attachCalls, hosts.desiredWrites, store.members[seatID].State.Stage)
	}
	// The gate qualifies the image the member's own host boots.
	if len(fleet.verifiedImages) == 0 || fleet.verifiedImages[0] != fleet.instances[0].ImageID {
		t.Fatalf("verified images = %v; want the member host's image %s", fleet.verifiedImages, fleet.instances[0].ImageID)
	}
	fleet.imageVerifyErr = nil
	controller.resolveArtifact = func(_ context.Context, digest, _, _ string) (AdmittedArtifact, error) {
		return AdmittedArtifact{Digest: digest, SourceDigest: strings.Repeat("f", 64)}, nil
	}
	verifiedCalls := fleet.imageVerifyCalls
	if err := controller.Tick(t.Context()); err != nil || store.casCalls != 0 ||
		fleet.imageVerifyCalls != verifiedCalls || store.members[seatID].State.Stage != StagePreparedAttach {
		t.Fatalf("observed attachment bypassed current runtime artifact admission: err=%v CAS=%d image=%d stage=%s",
			err, store.casCalls, fleet.imageVerifyCalls, store.members[seatID].State.Stage)
	}
	controller.resolveArtifact = func(_ context.Context, digest, _, _ string) (AdmittedArtifact, error) {
		return AdmittedArtifact{Digest: digest, SourceDigest: strings.Repeat("e", 64)}, nil
	}
	if err := controller.Tick(t.Context()); err != nil || store.casCalls != 1 ||
		fleet.imageVerifyCalls != verifiedCalls+1 || fleet.attachCalls != 0 ||
		store.members[seatID].State.Stage != StageAwaitingRuntimeContract {
		t.Fatalf("qualified observed attachment did not advance correctly: err=%v CAS=%d image=%d attach=%d stage=%s",
			err, store.casCalls, fleet.imageVerifyCalls, fleet.attachCalls, store.members[seatID].State.Stage)
	}
}

func TestControllerHoldsAttachmentStuckAttachingPastDeadline(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := newPlacementMemoryStore(t, intent)
	for memberID, member := range store.members {
		member.State.Stage = StageAwaitingAttach
		member.State.UpdatedAt = time.Now().UTC().Add(-5 * time.Minute)
		store.members[memberID] = member
	}
	instances := attachedInstances(t, intent)
	for index := range instances {
		instances[index].Attachments[0].State = "ATTACHING"
	}
	fleet := &placementTestFleet{instances: instances}
	hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, hosts, func(reason string) { holds = append(holds, reason) })

	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, reason := range holds {
		if strings.Contains(reason, "stuck ATTACHING") {
			t.Fatalf("attachment within its deadline was reported stuck: %s", reason)
		}
	}
	controller.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	holds = nil
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	stuck := false
	for _, reason := range holds {
		stuck = stuck || strings.Contains(reason, "stuck ATTACHING") && strings.Contains(reason, "force-detach-retry")
	}
	if !stuck || store.casCalls != 0 || hosts.desiredWrites != 0 || fleet.attachCalls != 0 {
		t.Fatalf("stuck attachment was not held with remediation: holds=%q CAS=%d desired=%d attach=%d",
			holds, store.casCalls, hosts.desiredWrites, fleet.attachCalls)
	}
}

func TestControllerWaitsForOCIReferenceToBecomeAttached(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := newPlacementMemoryStore(t, intent)
	for memberID, member := range store.members {
		member.State.Stage = StageAwaitingAttach
		store.members[memberID] = member
	}
	instances := attachedInstances(t, intent)
	for index := range instances {
		instances[index].Attachments[0].State = "ATTACHING"
	}
	fleet := &placementTestFleet{instances: instances}
	hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
	controller := startTestPlacementController(t, store, fleet, hosts, nil)

	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.casCalls != 0 || hosts.desiredWrites != 0 {
		t.Fatalf("ATTACHING attachment advanced or wrote desired state: CAS=%d desired=%d", store.casCalls, hosts.desiredWrites)
	}

	for index := range fleet.instances {
		fleet.instances[index].Attachments[0].State = "ATTACHED"
	}
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.casCalls != 1 {
		t.Fatalf("one tick performed %d state transitions, want one", store.casCalls)
	}
	if hosts.desiredWrites != 0 {
		t.Fatalf("ATTACHED state wrote host desired state %d times", hosts.desiredWrites)
	}
	if fleet.instances[0].Region != oci.RegionGRU {
		t.Fatal("test fleet region changed unexpectedly")
	}
}

func TestControllerMovesLegacyServingMemberToRuntimeHoldWhenHostIsLost(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := newPlacementMemoryStore(t, intent)
	store.members[permanentMember(oci.RegionGRU)] = VersionedMemberState{
		State:    testMemberState(t, intent, Seat{MemberID: "000000000082AXF7GZQT1D126Y", Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}, StageServing),
		Revision: 1,
	}
	store.members[elasticMember(oci.RegionGRU)] = VersionedMemberState{
		State:    testMemberState(t, intent, Seat{MemberID: "0000000000XG8SBD7XGE97V28G", Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic}, StageServing),
		Revision: 1,
	}
	instances := attachedInstances(t, intent)
	instances = instances[1:] // permanent-a has disappeared from the owned OCI view.
	fleet := &placementTestFleet{instances: instances}
	hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, hosts, func(reason string) { holds = append(holds, reason) })

	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := store.members[permanentMember(oci.RegionGRU)].State.Stage; got != StageAwaitingRuntimeContract {
		t.Fatalf("missing serving member stage = %q, want explicit hold", got)
	}
	if fleet.ensureCalls != 0 || fleet.attachCalls != 0 || hosts.desiredWrites != 0 {
		t.Fatalf("lost member was automatically replaced or launched: fleet=%#v desired=%d", fleet, hosts.desiredWrites)
	}
	if len(holds) != 1 {
		t.Fatalf("hold callbacks = %d, want one for the lost member", len(holds))
	}
}

func TestControllerPinsSignedProfileBeforeHostCreateAndUsesItOnRecovery(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := &placementMemoryStore{intents: []Intent{intent}, members: make(map[string]VersionedMemberState)}
	fleet := &placementTestFleet{ensureResult: &attachedInstances(t, intent)[0]}
	controller := startTestPlacementController(t, store, fleet, &placementTestHosts{}, nil)

	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	state := store.members[permanentMember(oci.RegionGRU)].State
	profile, err := intent.ManagedHostProfile(oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := intent.ProfileDigest(oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	rosterDigest, err := intent.CanonicalRosterDigest()
	if err != nil {
		t.Fatal(err)
	}
	row, err := intent.RosterRowForSeat(Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent})
	if err != nil {
		t.Fatal(err)
	}
	if store.casCalls != 1 || fleet.ensureCalls != 0 || state.Stage != StagePreparedHost ||
		state.CanonicalRosterRow != row || state.CanonicalRosterDigest != rosterDigest ||
		state.AuthorityReference != intent.CanonicalRoster.Authority ||
		state.IntentPayloadDigest != intent.PayloadDigest() || state.ManagedHostProfile != profile ||
		state.ManagedHostProfileDigest != profileDigest || state.IntentGeneration != intent.Generation {
		t.Fatalf("first CAS did not pin the committed profile before OCI: state=%+v CAS=%d ensures=%d", state, store.casCalls, fleet.ensureCalls)
	}

	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	state = store.members[permanentMember(oci.RegionGRU)].State
	if state.Stage != StageAwaitingHost || state.InstanceID != fleet.ensureResult.ID ||
		state.InstanceETag != fleet.ensureResult.ETag || len(fleet.ensureRequests) != 1 ||
		fleet.ensureRequests[0] != pinnedEnsureRequest(state) {
		t.Fatalf("host launch did not bind the pinned request and verified instance: state=%+v requests=%+v", state, fleet.ensureRequests)
	}

	restarted := startTestPlacementController(t, store, fleet, &placementTestHosts{}, nil)
	if err := restarted.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(fleet.ensureRequests) != 2 || fleet.ensureRequests[1] != fleet.ensureRequests[0] ||
		store.members[permanentMember(oci.RegionGRU)].State.CreateKey != state.CreateKey {
		t.Fatalf("recovery changed the immutable launch request: requests=%+v", fleet.ensureRequests)
	}
}

func TestControllerRejectsEnsuredHostThatDiffersFromPinnedProfile(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	for _, test := range []struct {
		name   string
		change func(*oci.Instance)
	}{
		{"compute memory", func(instance *oci.Instance) { instance.MemoryInGBs++ }},
		{"profile digest", func(instance *oci.Instance) { instance.PlacementProfileDigest = "0000000000V4MRM46HP1SNGDYW" }},
		{"owner", func(instance *oci.Instance) { instance.Owner = "0000000000V4MRM46HP1SNGDYW" }},
		{"fleet generation", func(instance *oci.Instance) { instance.Generation++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &placementMemoryStore{intents: []Intent{intent}, members: make(map[string]VersionedMemberState)}
			instance := attachedInstances(t, intent)[0]
			test.change(&instance)
			fleet := &placementTestFleet{ensureResult: &instance}
			controller := startTestPlacementController(t, store, fleet, &placementTestHosts{}, nil)
			if err := controller.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := controller.Tick(t.Context()); err == nil || fleet.ensureCalls != 1 || store.casCalls != 1 ||
				store.members[permanentMember(oci.RegionGRU)].State.Stage != StagePreparedHost {
				t.Fatalf("mismatched OCI response advanced the member: err=%v CAS=%d ensures=%d", err, store.casCalls, fleet.ensureCalls)
			}
		})
	}
}

func TestControllerHoldsUnpinnedChangedAndRemovedMembersBeforeOCI(t *testing.T) {
	base := committedTestIntent(t, validIntent(oci.RegionGRU))
	newGeneration := validIntent(oci.RegionGRU)
	newGeneration.Generation++
	newProfile := validIntent(oci.RegionGRU)
	newProfile.ManagedHostProfiles[0].Compute.MemoryInGBs++
	newGeneration = committedTestIntent(t, newGeneration)
	newProfile = committedTestIntent(t, newProfile)
	newPayload := committedTestIntent(t, validIntent(oci.RegionGRU, oci.RegionSFO))
	tests := []struct {
		name   string
		change func(*placementMemoryStore)
	}{
		{name: "legacy unpinned state", change: func(store *placementMemoryStore) {
			member := store.members[permanentMember(oci.RegionGRU)]
			member.State.SchemaVersion = 1
			member.State.CanonicalRosterRow = CanonicalRosterRow{}
			member.State.CanonicalRosterDigest = ""
			member.State.AuthorityReference = AuthorityReference{}
			member.State.IntentPayloadDigest = ""
			member.State.ManagedHostProfile = ManagedHostProfile{}
			member.State.ManagedHostProfileDigest = ""
			store.members[permanentMember(oci.RegionGRU)] = member
		}},
		{name: "changed canonical roster row", change: func(store *placementMemoryStore) {
			member := store.members[permanentMember(oci.RegionGRU)]
			member.State.CanonicalRosterRow = store.members[elasticMember(oci.RegionGRU)].State.CanonicalRosterRow
			store.members[permanentMember(oci.RegionGRU)] = member
		}},
		{name: "missing canonical roster digest", change: func(store *placementMemoryStore) {
			member := store.members[permanentMember(oci.RegionGRU)]
			member.State.CanonicalRosterDigest = ""
			store.members[permanentMember(oci.RegionGRU)] = member
		}},
		{name: "changed authority reference", change: func(store *placementMemoryStore) {
			member := store.members[permanentMember(oci.RegionGRU)]
			member.State.AuthorityReference.Epoch++
			store.members[permanentMember(oci.RegionGRU)] = member
		}},
		{name: "new signed generation", change: func(store *placementMemoryStore) {
			store.intents[0] = newGeneration
		}},
		{name: "changed signed regional profile", change: func(store *placementMemoryStore) {
			store.intents[0] = newProfile
		}},
		{name: "changed signed payload only", change: func(store *placementMemoryStore) {
			store.intents[0] = newPayload
		}},
		{name: "removed member", change: func(store *placementMemoryStore) {
			member := store.members[permanentMember(oci.RegionGRU)]
			member.State.Stage = StageRemoved
			member.State.HostGeneration = 1
			store.members[permanentMember(oci.RegionGRU)] = member
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newPlacementMemoryStore(t, base)
			member := store.members[permanentMember(oci.RegionGRU)]
			member.State.Stage = StagePreparedHost
			member.State.HostGeneration = 0
			store.members[permanentMember(oci.RegionGRU)] = member
			test.change(store)
			fleet := &placementTestFleet{}
			var holds []string
			controller := startTestPlacementController(t, store, fleet, &placementTestHosts{}, func(reason string) { holds = append(holds, reason) })
			if err := controller.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
			if fleet.ensureCalls != 0 || store.casCalls != 0 || len(holds) == 0 {
				t.Fatalf("unsafe member progressed: ensures=%d CAS=%d holds=%v", fleet.ensureCalls, store.casCalls, holds)
			}
		})
	}
}

func TestControllerHoldsConfiguredSeatWithoutMatchingSignedRosterRow(t *testing.T) {
	draft := validIntent(oci.RegionGRU)
	draft.CanonicalRoster.Rows[0].FailureDomain = "FAULT-DOMAIN-3"
	intent := committedTestIntent(t, draft)
	store := &placementMemoryStore{intents: []Intent{intent}, members: make(map[string]VersionedMemberState)}
	fleet := &placementTestFleet{}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, &placementTestHosts{}, func(reason string) { holds = append(holds, reason) })
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.casCalls != 0 || fleet.ensureCalls != 0 || len(holds) != 1 {
		t.Fatalf("configured failure domain mismatch prepared or launched a host: CAS=%d ensures=%d holds=%v", store.casCalls, fleet.ensureCalls, holds)
	}
}

func TestControllerRechecksExactRosterPinsBeforeHostRecoveryAndVolumeCreate(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seat := permanentMember(oci.RegionGRU)
	for _, stage := range []MemberStage{StageAwaitingHost, StagePreparedVolume} {
		for _, test := range []struct {
			name   string
			change func(*MemberState)
		}{
			{"row", func(state *MemberState) { state.CanonicalRosterRow.ServerName = "changed.example.test" }},
			{"roster digest", func(state *MemberState) { state.CanonicalRosterDigest = "" }},
			{"authority reference", func(state *MemberState) { state.AuthorityReference.Epoch++ }},
		} {
			t.Run(string(stage)+"/"+test.name, func(t *testing.T) {
				store := newPlacementMemoryStore(t, intent)
				member := store.members[seat]
				member.State.Stage = stage
				if stage == StageAwaitingHost {
					member.State.HostGeneration = 0
				} else {
					member.State.VolumeID = ""
					member.State.AttachmentID = ""
				}
				test.change(&member.State)
				store.members[seat] = member
				fleet := &placementTestFleet{}
				if stage == StagePreparedVolume {
					fleet.instances = attachedInstances(t, intent)
				}
				var holds []string
				controller := startTestPlacementController(t, store, fleet, &placementTestHosts{statuses: admittedStatuses(t, intent)}, func(reason string) { holds = append(holds, reason) })
				if err := controller.Tick(t.Context()); err != nil {
					t.Fatal(err)
				}
				if store.casCalls != 0 || fleet.ensureCalls != 0 || fleet.volumeCalls != 0 || len(holds) != 1 {
					t.Fatalf("drifted %s pin advanced member: CAS=%d ensures=%d volumes=%d holds=%v", stage, store.casCalls, fleet.ensureCalls, fleet.volumeCalls, holds)
				}
			})
		}
	}
}

func TestControllerHoldsWholePlacementBeforePreparingMissingSeat(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := newPlacementMemoryStore(t, intent)
	delete(store.members, permanentMember(oci.RegionGRU))
	elastic := store.members[elasticMember(oci.RegionGRU)]
	elastic.State.IntentPayloadDigest = ""
	elastic.State.ManagedHostProfile = ManagedHostProfile{}
	elastic.State.ManagedHostProfileDigest = ""
	store.members[elasticMember(oci.RegionGRU)] = elastic
	fleet := &placementTestFleet{}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, &placementTestHosts{}, func(reason string) { holds = append(holds, reason) })
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.casCalls != 0 || fleet.ensureCalls != 0 || len(holds) != 1 {
		t.Fatalf("stale sibling allowed a missing seat to prepare: CAS=%d ensures=%d holds=%v", store.casCalls, fleet.ensureCalls, holds)
	}
}

func TestControllerFailingPlacementDoesNotStarveLaterPlacement(t *testing.T) {
	failingDraft := validIntent(oci.RegionGRU)
	failingDraft.DatabaseID = "0000000000ZDFG8AVKATN4TM9W"
	failing := committedTestIntent(t, failingDraft)
	laterDraft := validIntent(oci.RegionGRU)
	laterDraft.DatabaseID = "00000000006GZX5HDQZN73AY33"
	later := committedTestIntent(t, laterDraft)
	store := &placementMemoryStore{intents: []Intent{failing, later}, members: make(map[string]VersionedMemberState)}
	launchErr := errors.New("injected OCI launch failure")
	fleet := &placementTestFleet{ensureErr: launchErr}
	controller := startTestPlacementController(t, store, fleet, &placementTestHosts{}, func(string) {})

	// First pass prepares the failing placement's first seat.
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Its host launch fails, yet the same pass still prepares the later
	// placement. The memory store keys members by seat alone, so that write
	// is observed through its CAS hook.
	reachedLater := false
	store.onCAS = func(state MemberState) error {
		reachedLater = reachedLater || state.DatabaseID == later.DatabaseID
		return nil
	}
	err := controller.Tick(t.Context())
	if !errors.Is(err, launchErr) || fleet.ensureCalls != 1 || !reachedLater {
		t.Fatalf("failing placement starved the later placement: err=%v ensures=%d reached=%v", err, fleet.ensureCalls, reachedLater)
	}
}

func TestControllerGrowsUndersizedRetainedVolumeAutomatically(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seat := Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}
	store := newPlacementMemoryStore(t, intent)
	member := store.members[seat.MemberID]
	member.State.Stage = StagePreparedVolume
	member.State.VolumeID, member.State.AttachmentID = "", ""
	store.members[seat.MemberID] = member
	// The test controller desires 50 GiB (32 GiB rounded up to OCI's minimum);
	// the volume was created under an earlier smaller profile.
	fleet := &placementTestFleet{instances: attachedInstances(t, intent), volumeResult: &oci.RetainedVolume{
		ID: "volume-created", CreateKey: volumeCreateKey(intent, seat), Region: oci.RegionGRU,
		Owner: "owner-a", Generation: 1, SizeGB: 40,
	}}
	hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
	controller := startTestPlacementController(t, store, fleet, hosts, nil)
	err := controller.Tick(t.Context())
	state := store.members[seat.MemberID].State
	if err != nil || len(fleet.resizeRequests) != 1 || fleet.resizeRequests[0].SizeGB != 50 ||
		fleet.resizeRequests[0].VolumeID != "volume-created" || state.Stage != StagePreparedAttach {
		t.Fatalf("automatic growth did not resize then advance: err=%v resizes=%+v stage=%s", err, fleet.resizeRequests, state.Stage)
	}
}

func TestControllerPreparesRetainedVolumeOnlyWithCurrentExactHost(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seat := Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}
	for _, test := range []struct {
		name           string
		change         func(*placementMemoryStore, *placementTestFleet, *placementTestHosts)
		wantCreate     bool
		wantVolumeCall bool
		wantError      bool
	}{
		{name: "current exact host", wantCreate: true},
		{name: "undersized observed volume", wantCreate: true,
			change: func(_ *placementMemoryStore, fleet *placementTestFleet, _ *placementTestHosts) {
				fleet.volumeResult.SizeGB = 1
			}},
		{name: "host missing", change: func(_ *placementMemoryStore, fleet *placementTestFleet, _ *placementTestHosts) {
			fleet.instances = nil
		}},
		{name: "profile drift", wantError: true, change: func(_ *placementMemoryStore, fleet *placementTestFleet, _ *placementTestHosts) {
			fleet.instances[0].MemoryInGBs++
		}},
		{name: "session missing", change: func(_ *placementMemoryStore, _ *placementTestFleet, hosts *placementTestHosts) {
			hosts.statuses = nil
		}},
		{name: "registration generation changed", change: func(_ *placementMemoryStore, _ *placementTestFleet, hosts *placementTestHosts) {
			hosts.statuses[0].Registration.Generation++
		}},
		// The member host's own image must qualify before its volume exists.
		{name: "host image not qualified", wantError: true, change: func(_ *placementMemoryStore, fleet *placementTestFleet, _ *placementTestHosts) {
			fleet.imageVerifyErr = oci.ErrImageNotQualified
		}},
		{name: "existing volume retained on host loss", change: func(store *placementMemoryStore, fleet *placementTestFleet, _ *placementTestHosts) {
			fleet.instances = nil
			member := store.members[seat.MemberID]
			member.State.VolumeID = "volume-existing"
			store.members[seat.MemberID] = member
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newPlacementMemoryStore(t, intent)
			member := store.members[seat.MemberID]
			member.State.Stage = StagePreparedVolume
			member.State.VolumeID = ""
			member.State.AttachmentID = ""
			store.members[seat.MemberID] = member
			fleet := &placementTestFleet{instances: attachedInstances(t, intent), volumeResult: &oci.RetainedVolume{
				ID: "volume-created", CreateKey: volumeCreateKey(intent, seat), Region: oci.RegionGRU,
				Owner: "owner-a", Generation: 1, SizeGB: 50,
			}}
			hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
			if test.change != nil {
				test.change(store, fleet, hosts)
			}
			before := store.members[seat.MemberID].State
			controller := startTestPlacementController(t, store, fleet, hosts, nil)
			err := controller.Tick(t.Context())
			if (err != nil) != test.wantError {
				t.Fatalf("Tick error = %v, wantError %t", err, test.wantError)
			}
			state := store.members[seat.MemberID].State
			if test.wantCreate {
				if fleet.volumeCalls != 1 || store.casCalls != 1 || state.VolumeID != "volume-created" || state.Stage != StagePreparedAttach {
					t.Fatalf("current host did not authorize exactly one retained volume: calls=%d CAS=%d state=%+v", fleet.volumeCalls, store.casCalls, state)
				}
			} else {
				wantCalls := 0
				if test.wantVolumeCall {
					wantCalls = 1
				}
				if fleet.volumeCalls != wantCalls || store.casCalls != 0 || !reflect.DeepEqual(state, before) {
					t.Fatalf("held volume altered durable placement: calls=%d CAS=%d state=%+v", fleet.volumeCalls, store.casCalls, state)
				}
			}
		})
	}
}

func TestControllerRejectsStaleManagedRegistrationBeforeAdmissionOrVolume(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seatID := permanentMember(oci.RegionGRU)
	for _, stage := range []MemberStage{StageAwaitingHost, StagePreparedVolume} {
		for _, test := range []struct {
			name   string
			change func(*host.Registration)
		}{
			{"missing placement", func(r *host.Registration) { r.ManagedPlacement = nil }},
			{"intent generation", func(r *host.Registration) { r.ManagedPlacement.IntentGeneration++ }},
			{"payload digest", func(r *host.Registration) { r.ManagedPlacement.IntentPayloadDigest = "0000000000RNVXNPAX5Y5BB8RY" }},
			{"roster digest", func(r *host.Registration) { r.ManagedPlacement.CanonicalRosterDigest = "0000000000RNVXNPAX5Y5BB8RY" }},
			{"profile digest", func(r *host.Registration) { r.ManagedPlacement.ManagedHostProfileDigest = "0000000000RNVXNPAX5Y5BB8RY" }},
			{"member incarnation", func(r *host.Registration) { r.ManagedMember.Scope.Incarnation = "000000000000c577dad95d2f8ab5a31e" }},
			{"host attempt", func(r *host.Registration) { r.ManagedMember.HostAttempt++ }},
			{"allocatable memory", func(r *host.Registration) { r.Capacity.MemoryBytes++ }},
			{"system reserve", func(r *host.Registration) { r.SystemReserveBytes++ }},
		} {
			t.Run(string(stage)+"/"+test.name, func(t *testing.T) {
				store := newPlacementMemoryStore(t, intent)
				member := store.members[seatID]
				member.State.Stage = stage
				member.State.VolumeID = ""
				member.State.AttachmentID = ""
				store.members[seatID] = member
				fleet := &placementTestFleet{instances: attachedInstances(t, intent)}
				hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
				test.change(&hosts.statuses[0].Registration)
				controller := startTestPlacementController(t, store, fleet, hosts, nil)
				if err := controller.Tick(t.Context()); err != nil {
					t.Fatal(err)
				}
				if state := store.members[seatID].State; state.Stage != stage || store.casCalls != 0 ||
					fleet.volumeCalls != 0 || fleet.ensureCalls != 0 || fleet.attachCalls != 0 {
					t.Fatalf("stale registration advanced %s or caused OCI effects: state=%+v CAS=%d fleet=%+v", stage, state, store.casCalls, fleet)
				}
			})
		}
	}
}

func TestControllerUsesStartOfTickPlacementAndHoldsItOnNextTick(t *testing.T) {
	intentA := committedTestIntent(t, validIntent(oci.RegionGRU))
	intentB := validIntent(oci.RegionGRU)
	intentB.Generation++
	intentB = committedTestIntent(t, intentB)
	store := newPlacementMemoryStore(t, intentA)
	member := store.members[permanentMember(oci.RegionGRU)]
	member.State.Stage = StagePreparedHost
	member.State.HostGeneration = 0
	store.members[permanentMember(oci.RegionGRU)] = member
	instance := attachedInstances(t, intentA)[0]
	fleet := &placementTestFleet{ensureResult: &instance}
	fleet.onObserve = func() { store.intents[0] = intentB; fleet.onObserve = nil }
	var holds []string
	controller := startTestPlacementController(t, store, fleet, &placementTestHosts{}, func(reason string) { holds = append(holds, reason) })
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if fleet.ensureCalls != 1 || store.casCalls != 1 || fleet.ensureRequests[0].PlacementGeneration != intentA.Generation ||
		store.members[permanentMember(oci.RegionGRU)].State.Stage != StageAwaitingHost {
		t.Fatalf("bounded A action did not use the initial signed snapshot: ensures=%d CAS=%d requests=%+v", fleet.ensureCalls, store.casCalls, fleet.ensureRequests)
	}
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if fleet.ensureCalls != 1 || store.casCalls != 1 || len(holds) == 0 {
		t.Fatalf("next tick retried old A after observing B: ensures=%d CAS=%d holds=%v", fleet.ensureCalls, store.casCalls, holds)
	}
}

func TestControllerAllowsLiveETagChurnButRejectsImmutableInstanceDrift(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	newFixture := func(t *testing.T) (*placementMemoryStore, *placementTestFleet, *Controller) {
		t.Helper()
		store := newPlacementMemoryStore(t, intent)
		member := store.members[permanentMember(oci.RegionGRU)]
		member.State.Stage = StageAwaitingHost
		member.State.HostGeneration = 0
		store.members[permanentMember(oci.RegionGRU)] = member
		fleet := &placementTestFleet{instances: attachedInstances(t, intent)}
		controller := startTestPlacementController(t, store, fleet, &placementTestHosts{statuses: admittedStatuses(t, intent)}, nil)
		return store, fleet, controller
	}
	store, fleet, controller := newFixture(t)
	fleet.instances[0].ETag = "etag-new"
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatalf("legitimate live ETag churn was held: %v", err)
	}
	if state := store.members[permanentMember(oci.RegionGRU)].State; state.InstanceETag != "etag-new" || state.Stage != StagePreparedAttach {
		t.Fatalf("verified live ETag was not rebound on admission: %+v", state)
	}

	for _, test := range []struct {
		name   string
		change func(*oci.Instance)
	}{
		{"shape", func(instance *oci.Instance) { instance.Shape = "VM.Standard.E5.Flex" }},
		{"profile digest", func(instance *oci.Instance) { instance.PlacementProfileDigest = "0000000000V4MRM46HP1SNGDYW" }},
		{"placement generation", func(instance *oci.Instance) { instance.PlacementGeneration++ }},
		{"owner", func(instance *oci.Instance) { instance.Owner = "0000000000V4MRM46HP1SNGDYW" }},
		{"fleet generation", func(instance *oci.Instance) { instance.Generation++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, fleet, controller := newFixture(t)
			test.change(&fleet.instances[0])
			if err := controller.Tick(t.Context()); err == nil || store.casCalls != 0 || fleet.ensureCalls != 0 {
				t.Fatalf("immutable OCI drift was accepted: err=%v CAS=%d ensures=%d", err, store.casCalls, fleet.ensureCalls)
			}
		})
	}
}

// A member host launched from an earlier image keeps its seat after the
// cell pins a newer one, only while the cell's allow-list names its image.
func TestControllerKeepsMemberHostsOfAllowedEarlierImages(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	earlier := "ocid1.image.oc1..placement-earlier"
	for _, test := range []struct {
		name    string
		allowed func() []string
		image   string
		member  bool
	}{
		{"earlier image allowed", func() []string { return []string{earlier} }, earlier, true},
		{"no allow-list", nil, earlier, false},
		{"other image allowed", func() []string { return []string{"ocid1.image.oc1..placement-other"} }, earlier, false},
		// The descriptor binds the image the host was launched from.
		{"descriptor of another image", func() []string { return []string{earlier} }, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newPlacementMemoryStore(t, intent)
			member := store.members[permanentMember(oci.RegionGRU)]
			member.State.Stage = StageAwaitingHost
			member.State.HostGeneration = 0
			store.members[permanentMember(oci.RegionGRU)] = member
			fleet := &placementTestFleet{instances: attachedInstances(t, intent)}
			for index := range fleet.instances {
				instance := &fleet.instances[index]
				state := store.members[seatOfNode(t, store, instance.Node)].State
				instance.ImageID = earlier
				if test.image != "" {
					instance.BootDescriptorSHA256 = placementTestBootDigest(t, state, test.image)
				}
			}
			controller := startTestPlacementController(t, store, fleet, &placementTestHosts{statuses: admittedStatuses(t, intent)}, nil)
			controller.config.AllowedImages = test.allowed
			err := controller.Tick(t.Context())
			admitted := store.members[permanentMember(oci.RegionGRU)].State.Stage == StagePreparedAttach
			if test.member != (err == nil && admitted) {
				t.Fatalf("Tick = %v, admitted %t; want member %t", err, admitted, test.member)
			}
		})
	}
}

func seatOfNode(t *testing.T, store *placementMemoryStore, node string) string {
	t.Helper()
	for seat, member := range store.members {
		if member.State.HostNode == node {
			return seat
		}
	}
	t.Fatalf("no seat for node %s", node)
	return ""
}

func placementTestBootDigest(t *testing.T, state MemberState, imageID string) string {
	t.Helper()
	digest, err := hostboot.Descriptor{
		SchemaVersion: hostboot.SchemaVersion, Cell: "gru", Region: "GRU", Node: state.HostNode,
		Owner: "owner-a", CreateKey: state.CreateKey, ImageID: imageID,
		FleetGeneration: 1, DatabaseID: state.DatabaseID, PartitionID: state.PartitionID,
		SeatID: state.MemberID, HostAttempt: state.HostAttempt, IntentGeneration: state.IntentGeneration,
		IntentPayloadDigest: state.IntentPayloadDigest, CanonicalRosterDigest: state.CanonicalRosterDigest,
		ManagedHostProfileDigest: state.ManagedHostProfileDigest, RuntimeManifestDigest: state.RuntimeManifestDigest,
	}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func startTestPlacementController(t *testing.T, store Store, fleet oci.Fleet, hosts HostView, onHold func(string)) *Controller {
	t.Helper()
	writer, ok := hosts.(DesiredWriter)
	if !ok {
		t.Fatal("test host view lacks desired writer")
	}
	controller, err := StartController(t.Context(), Config{
		Cell: "gru", Region: oci.RegionGRU, FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		ManagedOwner: "owner-a", FleetGeneration: 1, Environment: "production", MemberRole: "terrabase",
		ImageID:   "ocid1.image.oc1..placement-test",
		Resources: Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 32 << 30}, OnHold: onHold,
	}, store, placementTestFencer{}, fleet, hosts, writer,
		func(_ context.Context, digest, _, _ string) (AdmittedArtifact, error) {
			return AdmittedArtifact{Digest: digest, SourceDigest: strings.Repeat("e", 64)}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func committedTestIntent(t *testing.T, intent Intent) Intent {
	t.Helper()
	payload, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := DecodeCommittedIntent(payload)
	if err != nil {
		t.Fatal(err)
	}
	return committed
}

func newPlacementMemoryStore(t *testing.T, intent Intent) *placementMemoryStore {
	t.Helper()
	store := &placementMemoryStore{intents: []Intent{intent}, members: make(map[string]VersionedMemberState)}
	for _, seat := range []Seat{
		{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent},
		{MemberID: elasticMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic},
	} {
		store.members[seat.MemberID] = VersionedMemberState{State: testMemberState(t, intent, seat, StageAwaitingRuntimeContract), Revision: 1}
	}
	return store
}

func testMemberState(t *testing.T, intent Intent, seat Seat, stage MemberStage) MemberState {
	t.Helper()
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
	attempt := uint64(1)
	state := MemberState{
		SchemaVersion: managedUpdateMemberStateSchemaVersion, DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
		MemberID: seat.MemberID, Region: seat.Region, FailureDomain: seat.FailureDomain, Kind: seat.Kind,
		Stage: stage, CreateKey: hostCreateKey(intent, seat, attempt), HostAttempt: attempt,
		HostNode: "node-" + strings.ToLower(seat.MemberID), InstanceID: "instance-" + seat.MemberID,
		InstanceETag: "etag-1", VolumeID: "volume-" + seat.MemberID,
		AttachmentID: "attachment-" + seat.MemberID, HostGeneration: 1,
		CanonicalRosterRow: row, CanonicalRosterDigest: rosterDigest, AuthorityReference: intent.CanonicalRoster.Authority,
		RuntimeManifest: manifest, RuntimeManifestDigest: manifestDigest,
		IntentPayloadDigest: intent.PayloadDigest(), ManagedHostProfile: profile, ManagedHostProfileDigest: profileDigest,
		IntentGeneration: intent.Generation, DesiredGeneration: 1,
		OperationID: memberOperationID(intent, seat.MemberID, attempt, "test"), UpdatedAt: time.Now().UTC(),
	}
	if stage == StagePreparedHost || stage == StageAwaitingHost {
		state.HostGeneration = 0
	}
	if stage == StagePreparedDesired || stage == StageAwaitingHealthy {
		state.AttachmentDevice, state.AttachmentETag = "/dev/sdb", "attachment-etag"
	}
	return state
}

func TestTerminalTargetsUseExactAdmittedSeatsAndDurableAttemptKeys(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seats, err := DesiredSeats(intent, map[oci.Region][]string{
		oci.RegionGRU: {"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := testMemberState(t, intent, seats[0], StageAwaitingRuntimeContract)
	states := []VersionedMemberState{{State: state, Revision: 1}}
	targets, err := TerminalTargetsForRegion(intent, oci.RegionGRU,
		[]string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"}, states)
	if err != nil || len(targets) != 2 {
		t.Fatalf("derive exact terminal targets: %+v, %v", targets, err)
	}
	for index, seat := range seats {
		row, err := intent.RosterRowForSeat(seat)
		if err != nil {
			t.Fatal(err)
		}
		if targets[index].SeatID != seat.MemberID || targets[index].MemberID != row.MemberID ||
			targets[index].HostCreateKey != hostCreateKey(intent, seat, 1) ||
			targets[index].DataCreateKey != volumeCreateKey(intent, seat) {
			t.Fatalf("terminal target changed signed seat or durable create key: %+v", targets[index])
		}
	}
	states[0].State.CreateKey = "00000000005V7B700A13WSMMS8"
	if _, err := TerminalTargetsForRegion(intent, oci.RegionGRU,
		[]string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"}, states); err == nil {
		t.Fatal("terminal plan accepted a durable member with a different host create key")
	}
}

func attachedInstances(t *testing.T, intent Intent) []oci.Instance {
	t.Helper()
	seats := []Seat{
		{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent},
		{MemberID: elasticMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic},
	}
	instances := make([]oci.Instance, 0, len(seats))
	for _, seat := range seats {
		state := testMemberState(t, intent, seat, StageAwaitingRuntimeContract)
		descriptor := hostboot.Descriptor{
			SchemaVersion: hostboot.SchemaVersion, Cell: "gru", Region: "GRU", Node: state.HostNode,
			Owner: "owner-a", CreateKey: state.CreateKey, ImageID: "ocid1.image.oc1..placement-test",
			FleetGeneration: 1, DatabaseID: state.DatabaseID, PartitionID: state.PartitionID,
			SeatID: state.MemberID, HostAttempt: state.HostAttempt, IntentGeneration: state.IntentGeneration,
			IntentPayloadDigest: state.IntentPayloadDigest, CanonicalRosterDigest: state.CanonicalRosterDigest,
			ManagedHostProfileDigest: state.ManagedHostProfileDigest, RuntimeManifestDigest: state.RuntimeManifestDigest,
		}
		bootDigest, err := descriptor.Digest()
		if err != nil {
			t.Fatal(err)
		}
		privateIP, _, err := net.SplitHostPort(state.RuntimeManifest.ReplicationListenAddress)
		if err != nil {
			t.Fatal(err)
		}
		instances = append(instances, oci.Instance{
			ID: state.InstanceID, Node: state.HostNode, CreateKey: state.CreateKey, Region: seat.Region,
			PrivateIP:  privateIP,
			Generation: 1, Owner: "owner-a", FaultDomain: seat.FailureDomain,
			Shape: state.ManagedHostProfile.Compute.Shape, WholeOCPUs: state.ManagedHostProfile.Compute.WholeOCPUs,
			MemoryInGBs:            state.ManagedHostProfile.Compute.MemoryInGBs,
			PlacementProfileDigest: state.ManagedHostProfileDigest, PlacementGeneration: state.IntentGeneration,
			ImageID: descriptor.ImageID, BootDescriptorSHA256: bootDigest,
			ETag: state.InstanceETag, State: "RUNNING",
			Attachments: []oci.Attachment{{ID: state.AttachmentID, VolumeID: state.VolumeID, InstanceID: state.InstanceID, ETag: "attachment-etag", State: "ATTACHED"}},
		})
	}
	return instances
}

func admittedStatuses(t *testing.T, intent Intent) []host.HostStatus {
	t.Helper()
	statuses := make([]host.HostStatus, 0, 2)
	for _, seat := range []Seat{
		{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent},
		{MemberID: elasticMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic},
	} {
		state := testMemberState(t, intent, seat, StageAwaitingRuntimeContract)
		roster := intent.CanonicalRoster
		row := state.CanonicalRosterRow
		statuses = append(statuses, host.HostStatus{Verified: true, SessionExpiresAt: time.Now().Add(time.Minute), Registration: host.Registration{
			Cell: "gru", Node: state.HostNode, FailureDomain: seat.FailureDomain, Environment: "production",
			Roles: []string{"terrabase"}, Generation: 1,
			Capacity:           host.Capacity{CPU: 4, MemoryBytes: int64(state.ManagedHostProfile.AllocatableMemoryBytes), DiskBytes: 128 << 30},
			SystemReserveBytes: int64(state.ManagedHostProfile.SystemReserveBytes),
			ManagedOCI: &host.ManagedOCIBinding{Region: string(oci.RegionGRU), InstanceID: state.InstanceID,
				Owner: "owner-a", FleetGeneration: 1, CreateKey: state.CreateKey},
			ManagedMember: &host.ManagedMemberBinding{Scope: host.MemberScope{
				ClusterID: roster.ClusterID, TenantID: roster.TenantID, DatabaseID: roster.DatabaseID,
				ShardID: roster.ShardID, MemberID: row.MemberID, Incarnation: row.Incarnation,
			}, HostAttempt: state.HostAttempt},
			ManagedPlacement: &host.ManagedPlacementBinding{
				DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, SeatID: state.MemberID,
				IntentGeneration: state.IntentGeneration, IntentPayloadDigest: state.IntentPayloadDigest,
				CanonicalRosterDigest: state.CanonicalRosterDigest, ManagedHostProfileDigest: state.ManagedHostProfileDigest,
			},
		}})
	}
	return statuses
}

type placementMemoryStore struct {
	intents  []Intent
	members  map[string]VersionedMemberState
	casCalls int
	onCAS    func(MemberState) error
}

func (*placementMemoryStore) ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error) {
	return authority.LogEntry{}, authority.ErrNotFound
}

func (store *placementMemoryStore) ListIntents(context.Context) ([]Intent, error) {
	return slices.Clone(store.intents), nil
}

func (store *placementMemoryStore) ListMembers(_ context.Context, databaseID, partitionID string) ([]VersionedMemberState, error) {
	result := make([]VersionedMemberState, 0)
	for _, member := range store.members {
		if member.State.DatabaseID == databaseID && member.State.PartitionID == partitionID {
			result = append(result, member)
		}
	}
	return result, nil
}

func (store *placementMemoryStore) ReadMember(_ context.Context, databaseID, partitionID, seatID string) (VersionedMemberState, error) {
	member, exists := store.members[seatID]
	if !exists || member.State.DatabaseID != databaseID || member.State.PartitionID != partitionID {
		return VersionedMemberState{}, ErrMemberNotFound
	}
	return member, nil
}

func (store *placementMemoryStore) CompareAndSwap(_ context.Context, expected uint64, state MemberState) (uint64, error) {
	if store.onCAS != nil {
		if err := store.onCAS(state); err != nil {
			return 0, err
		}
	}
	current, exists := store.members[state.MemberID]
	if expected == 0 && exists || expected != 0 && (!exists || current.Revision != expected) {
		return 0, ErrStoreConflict
	}
	if err := state.Validate(); err != nil {
		return 0, err
	}
	store.casCalls++
	revision := expected + 1
	store.members[state.MemberID] = VersionedMemberState{State: state, Revision: revision}
	return revision, nil
}

type placementTestFencer struct{}

func (placementTestFencer) Current() authority.Snapshot {
	return authority.Snapshot{CandidateID: "0000000000GR3712FB1A87M2H7", OwnerID: "00000000004AS2NC5H2SW57SZG", Leader: true, Ready: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}
}

func (placementTestFencer) Guard(context.Context, uint64) error { return nil }

func (placementTestFencer) ReadManagedUpdate(context.Context, string, string) (authority.LogEntry, error) {
	return authority.LogEntry{}, authority.ErrNotFound
}

func (placementTestFencer) ReadManagedUpdateOperation(context.Context, string, string, string) ([]authority.LogEntry, error) {
	return nil, authority.ErrNotFound
}

func (placementTestFencer) ListManagedUpdates(context.Context, string, string) ([]authority.LogEntry, error) {
	return []authority.LogEntry{}, nil
}

func (placementTestFencer) BeginActiveWorkloadEffect(context.Context, uint64, authority.WorkloadScope) (func(), error) {
	return func() {}, nil
}

type placementTestHosts struct {
	statuses      []host.HostStatus
	desired       []host.Desired
	desiredWrites int
	onListHosts   func()
}

func (hosts *placementTestHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	if hosts.onListHosts != nil {
		hosts.onListHosts()
	}
	return slices.Clone(hosts.statuses), nil
}

func (hosts *placementTestHosts) ListDesired(context.Context, string) ([]host.Desired, error) {
	return slices.Clone(hosts.desired), nil
}

func (hosts *placementTestHosts) ApplyDesired(_ context.Context, desired host.Desired) (host.Receipt, error) {
	hosts.desiredWrites++
	hosts.desired = append(hosts.desired, desired)
	return host.Receipt{Generation: desired.Generation, Revision: uint64(hosts.desiredWrites)}, nil
}

type placementTestFleet struct {
	instances        []oci.Instance
	ensureResult     *oci.Instance
	ensureErr        error
	ensureRequests   []oci.EnsureRequest
	volumeResult     *oci.RetainedVolume
	onObserve        func()
	ensureCalls      int
	volumeCalls      int
	attachCalls      int
	imageVerifyCalls int
	imageVerifyErr   error
	cordonCalls      int
	terminateCalls   int
	resizeRequests   []oci.VolumeResizeRequest
	verifiedImages   []string
}

func (fleet *placementTestFleet) Region() oci.Region { return oci.RegionGRU }
func (fleet *placementTestFleet) VerifyHostImage(_ context.Context, imageID string) error {
	fleet.imageVerifyCalls++
	fleet.verifiedImages = append(fleet.verifiedImages, imageID)
	return fleet.imageVerifyErr
}
func (fleet *placementTestFleet) Observe(context.Context) ([]oci.Instance, error) {
	if fleet.onObserve != nil {
		fleet.onObserve()
	}
	return slices.Clone(fleet.instances), nil
}
func (fleet *placementTestFleet) EnsureHost(_ context.Context, request oci.EnsureRequest) (oci.Instance, error) {
	fleet.ensureCalls++
	fleet.ensureRequests = append(fleet.ensureRequests, request)
	if fleet.ensureErr != nil && fleet.ensureCalls == 1 {
		return oci.Instance{}, fleet.ensureErr
	}
	if fleet.ensureResult == nil {
		return oci.Instance{}, errors.New("unexpected EnsureHost")
	}
	return *fleet.ensureResult, nil
}
func (fleet *placementTestFleet) CreateRetainedVolume(context.Context, oci.VolumeCreateRequest) (oci.RetainedVolume, error) {
	fleet.volumeCalls++
	if fleet.volumeResult == nil {
		return oci.RetainedVolume{}, errors.New("unexpected CreateRetainedVolume")
	}
	return *fleet.volumeResult, nil
}
func (fleet *placementTestFleet) ResizeRetainedVolume(_ context.Context, request oci.VolumeResizeRequest) (oci.RetainedVolume, error) {
	fleet.resizeRequests = append(fleet.resizeRequests, request)
	if fleet.volumeResult == nil || fleet.volumeResult.ID != request.VolumeID {
		return oci.RetainedVolume{}, errors.New("unexpected ResizeRetainedVolume")
	}
	resized := *fleet.volumeResult
	resized.SizeGB = request.SizeGB
	return resized, nil
}
func (fleet *placementTestFleet) Cordon(context.Context, string, string) error {
	fleet.cordonCalls++
	return errors.New("unexpected Cordon")
}
func (*placementTestFleet) RequestDrain(context.Context, string, string) error {
	return errors.New("unexpected RequestDrain")
}
func (fleet *placementTestFleet) AttachRetainedVolume(context.Context, oci.VolumeAttachRequest) (oci.Attachment, error) {
	fleet.attachCalls++
	return oci.Attachment{}, errors.New("unexpected AttachRetainedVolume")
}
func (*placementTestFleet) Detach(context.Context, string, string, string, oci.WriterStopEvidence) error {
	return errors.New("unexpected Detach")
}
func (fleet *placementTestFleet) Terminate(context.Context, string, string, oci.WriterStopEvidence) error {
	fleet.terminateCalls++
	return errors.New("unexpected Terminate")
}

var _ Store = (*placementMemoryStore)(nil)
var _ HostView = (*placementTestHosts)(nil)
var _ oci.Fleet = (*placementTestFleet)(nil)

func ExamplevolumeSizeGB() {
	size, err := volumeSizeGB(51 << 30)
	if err != nil {
		panic(err)
	}
	fmt.Println(size)
	// Output: 51
}
