package placement

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/failover"
)

// reattachTestFleet adds the reattach boundary to the placement test fleet.
// Its attachments are the OCI attachment history of the one test volume.
type reattachTestFleet struct {
	*placementTestFleet
	states         map[string]string
	attachments    []oci.Attachment
	detaches       []oci.FencedDetachRequest
	attachRequests []oci.VolumeAttachRequest
	permits        []oci.VolumeMountPermit
}

func (fleet *reattachTestFleet) FencedInstanceState(_ context.Context, id string) (string, error) {
	state, ok := fleet.states[id]
	if !ok {
		return "", errors.New("instance not found")
	}
	return state, nil
}

func (fleet *reattachTestFleet) RetainedVolumeAttachments(context.Context, string) ([]oci.Attachment, error) {
	return append([]oci.Attachment(nil), fleet.attachments...), nil
}

func (fleet *reattachTestFleet) DetachFencedAttachment(_ context.Context, request oci.FencedDetachRequest) error {
	if fleet.states[request.InstanceID] != "TERMINATED" {
		return oci.ErrWriterStopUnverified
	}
	fleet.detaches = append(fleet.detaches, request)
	for index := range fleet.attachments {
		if fleet.attachments[index].ID == request.AttachmentID {
			fleet.attachments[index].State = "DETACHED"
		}
	}
	return nil
}

func (fleet *reattachTestFleet) AttachRetainedVolume(_ context.Context, request oci.VolumeAttachRequest) (oci.Attachment, error) {
	fleet.attachRequests = append(fleet.attachRequests, request)
	attachment := oci.Attachment{ID: "ocid1.volumeattachment.replacement", VolumeID: request.VolumeID,
		InstanceID: request.InstanceID, State: "ATTACHED", ETag: "replacement-etag", Device: "/dev/oracleoci/oraclevdb"}
	fleet.attachments = append(fleet.attachments, attachment)
	return attachment, nil
}

func (fleet *reattachTestFleet) GrantVolumeMountExisting(_ context.Context, permit oci.VolumeMountPermit) error {
	fleet.permits = append(fleet.permits, permit)
	return nil
}

func (fleet *reattachTestFleet) HasVolumeMountExisting(_ context.Context, permit oci.VolumeMountPermit) (bool, error) {
	for _, granted := range fleet.permits {
		if granted == permit {
			return true, nil
		}
	}
	return false, nil
}

func TestReattachMovesTheLostMembersVolumeOnlyAfterTermination(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seat := Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}
	store := newPlacementMemoryStore(t, intent)
	lost := store.members[seat.MemberID].State
	replacement, err := replacementMemberState(intent, seat, lost)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.PreviousInstanceID != lost.InstanceID {
		t.Fatalf("replacement does not remember its lost instance: %q", replacement.PreviousInstanceID)
	}
	replacement.InstanceID, replacement.HostNode = "ocid1.instance.replacement", lost.HostNode
	replacement.HostGeneration, replacement.Stage = 1, StagePreparedAttach
	store.members[seat.MemberID] = VersionedMemberState{State: replacement, Revision: 1}

	fleet := &reattachTestFleet{
		placementTestFleet: &placementTestFleet{},
		states:             map[string]string{lost.InstanceID: "STOPPED", replacement.InstanceID: "RUNNING"},
		attachments: []oci.Attachment{{ID: lost.AttachmentID, VolumeID: lost.VolumeID, InstanceID: lost.InstanceID,
			State: "ATTACHED", ETag: "lost-etag"}},
	}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, &placementTestHosts{},
		func(reason string) { holds = append(holds, reason) })
	start := time.Now().UTC()
	controller.now = func() time.Time { return start }
	step := func() (bool, MemberState) {
		t.Helper()
		holds = nil
		acted, err := controller.reattachRetainedVolume(t.Context(), 1, intent, seat, store.members[seat.MemberID])
		if err != nil {
			t.Fatal(err)
		}
		return acted, store.members[seat.MemberID].State
	}

	// A STOPPED instance can start again: nothing moves.
	if acted, state := step(); acted || len(fleet.detaches) != 0 || state.AttachRequestedAt.IsZero() ||
		!strings.Contains(strings.Join(holds, "\n"), "TERMINATED") {
		t.Fatalf("unfenced host: acted=%v detaches=%d state=%+v holds=%q", acted, len(fleet.detaches), state, holds)
	}
	fleet.states[lost.InstanceID] = "TERMINATED"
	if acted, _ := step(); !acted || len(fleet.detaches) != 1 || fleet.detaches[0].ExpectedETag != "lost-etag" {
		t.Fatalf("fenced detach: acted=%v detaches=%+v", acted, fleet.detaches)
	}
	if acted, _ := step(); !acted || len(fleet.attachRequests) != 1 || !fleet.attachRequests[0].AllowDetachedHistory ||
		fleet.attachRequests[0].InstanceID != replacement.InstanceID ||
		fleet.attachRequests[0].IdempotencyKey != memberOperationID(intent, seat.MemberID, 2, "attach-volume") {
		t.Fatalf("replacement attach: acted=%v requests=%+v", acted, fleet.attachRequests)
	}
	if acted, state := step(); !acted || len(fleet.permits) != 1 || state.Stage != StagePreparedAttach {
		t.Fatalf("mount permit: acted=%v permits=%+v stage=%s", acted, fleet.permits, state.Stage)
	}
	permit := fleet.permits[0]
	if permit.FencedInstanceID != lost.InstanceID || permit.ReplacementInstanceID != replacement.InstanceID ||
		permit.AttachmentID != "ocid1.volumeattachment.replacement" {
		t.Fatalf("mount permit = %+v", permit)
	}
	acted, state := step()
	if !acted || state.Stage != StageAwaitingRuntimeContract || state.AttachmentID != permit.AttachmentID ||
		!state.AttachRequestedAt.IsZero() || state.PreviousInstanceID != lost.InstanceID {
		t.Fatalf("reattach completion: acted=%v state=%+v", acted, state)
	}
	if len(fleet.detaches) != 1 || len(fleet.attachRequests) != 1 || len(fleet.permits) != 1 {
		t.Fatalf("reattach repeated an effect: detaches=%d attaches=%d permits=%d",
			len(fleet.detaches), len(fleet.attachRequests), len(fleet.permits))
	}
}

func TestReattachHoldsOnALiveThirdAttachmentAndUnsupportedFleets(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seat := Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}
	store := newPlacementMemoryStore(t, intent)
	lost := store.members[seat.MemberID].State
	replacement, err := replacementMemberState(intent, seat, lost)
	if err != nil {
		t.Fatal(err)
	}
	replacement.InstanceID, replacement.HostGeneration, replacement.Stage = "ocid1.instance.replacement", 1, StagePreparedAttach
	store.members[seat.MemberID] = VersionedMemberState{State: replacement, Revision: 1}
	fleet := &reattachTestFleet{
		placementTestFleet: &placementTestFleet{},
		states:             map[string]string{lost.InstanceID: "TERMINATED"},
		attachments: []oci.Attachment{{ID: "ocid1.volumeattachment.third", VolumeID: lost.VolumeID,
			InstanceID: "ocid1.instance.third", State: "ATTACHED", ETag: "third"}},
	}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, &placementTestHosts{},
		func(reason string) { holds = append(holds, reason) })
	acted, err := controller.reattachRetainedVolume(t.Context(), 1, intent, seat, store.members[seat.MemberID])
	if err != nil || acted || len(fleet.detaches)+len(fleet.attachRequests) != 0 ||
		!strings.Contains(strings.Join(holds, "\n"), "unrelated instance") {
		t.Fatalf("third live attachment: acted=%v err=%v holds=%q", acted, err, holds)
	}

	plain := &placementTestFleet{}
	holds = nil
	controller = startTestPlacementController(t, store, plain, &placementTestHosts{},
		func(reason string) { holds = append(holds, reason) })
	acted, err = controller.reattachRetainedVolume(t.Context(), 1, intent, seat, store.members[seat.MemberID])
	if err != nil || acted || plain.attachCalls != 0 || !strings.Contains(strings.Join(holds, "\n"), "does not support") {
		t.Fatalf("unsupported fleet: acted=%v err=%v holds=%q", acted, err, holds)
	}
}

func TestReattachReportsFailedFenceLookupsAndRejectsAStaleEpoch(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seat := Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}
	store := newPlacementMemoryStore(t, intent)
	lost := store.members[seat.MemberID].State
	replacement, err := replacementMemberState(intent, seat, lost)
	if err != nil {
		t.Fatal(err)
	}
	replacement.InstanceID, replacement.HostGeneration, replacement.Stage = "ocid1.instance.replacement", 1, StagePreparedAttach
	replacement.AttachRequestedAt = time.Now().UTC()
	store.members[seat.MemberID] = VersionedMemberState{State: replacement, Revision: 1}
	// The lost instance lookup fails: that is an error, not a wait.
	fleet := &reattachTestFleet{
		placementTestFleet: &placementTestFleet{},
		states:             map[string]string{},
		attachments: []oci.Attachment{{ID: lost.AttachmentID, VolumeID: lost.VolumeID, InstanceID: lost.InstanceID,
			State: "ATTACHED", ETag: "lost-etag"}},
	}
	controller := startTestPlacementController(t, store, fleet, &placementTestHosts{}, func(string) {})
	acted, err := controller.reattachRetainedVolume(t.Context(), 1, intent, seat, store.members[seat.MemberID])
	if acted || !errors.Is(err, failover.ErrFenceUnobserved) || len(fleet.detaches) != 0 {
		t.Fatalf("failed fence lookup: acted=%v err=%v detaches=%d", acted, err, len(fleet.detaches))
	}

	// Inputs read under another epoch never drive an effect.
	fleet.states[lost.InstanceID] = "TERMINATED"
	acted, err = controller.reattachRetainedVolume(t.Context(), 7, intent, seat, store.members[seat.MemberID])
	if acted || !errors.Is(err, authority.ErrFenced) || len(fleet.detaches) != 0 {
		t.Fatalf("stale epoch: acted=%v err=%v detaches=%d", acted, err, len(fleet.detaches))
	}
	if acted, err := controller.reattachRetainedVolume(t.Context(), 1, intent, seat, store.members[seat.MemberID]); err != nil ||
		!acted || len(fleet.detaches) != 1 {
		t.Fatalf("current epoch: acted=%v err=%v detaches=%d", acted, err, len(fleet.detaches))
	}
}

func TestMemberStateRejectsAnInconsistentPreviousInstance(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := newPlacementMemoryStore(t, intent)
	state := store.members[permanentMember(oci.RegionGRU)].State
	state.PreviousInstanceID = "ocid1.instance.previous"
	if err := state.Validate(); err == nil {
		t.Fatal("a first host attempt accepted a previous instance")
	}
	state.HostAttempt = 2
	if err := state.Validate(); err != nil {
		t.Fatalf("replacement attempt with a previous instance: %v", err)
	}
	state.PreviousInstanceID = state.InstanceID
	if err := state.Validate(); err == nil {
		t.Fatal("a member accepted its own instance as its previous instance")
	}
}
