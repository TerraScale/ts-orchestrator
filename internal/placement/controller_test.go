package placement

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

func TestControllerHoldsAfterAttachedVolumeWithoutRuntimeContract(t *testing.T) {
	intent := validIntent(oci.RegionGRU)
	store := newPlacementMemoryStore(intent)
	fleet := &placementTestFleet{instances: attachedInstances(intent)}
	hosts := &placementTestHosts{statuses: admittedStatuses(intent)}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, hosts, func(reason string) { holds = append(holds, reason) })

	if err := controller.Tick(context.Background()); err != nil {
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

func TestControllerWaitsForOCIReferenceToBecomeAttached(t *testing.T) {
	intent := validIntent(oci.RegionGRU)
	store := newPlacementMemoryStore(intent)
	for memberID, member := range store.members {
		member.State.Stage = StageAwaitingAttach
		store.members[memberID] = member
	}
	instances := attachedInstances(intent)
	for index := range instances {
		instances[index].Attachments[0].State = "ATTACHING"
	}
	fleet := &placementTestFleet{instances: instances}
	hosts := &placementTestHosts{statuses: admittedStatuses(intent)}
	controller := startTestPlacementController(t, store, fleet, hosts, nil)

	if err := controller.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.casCalls != 0 || hosts.desiredWrites != 0 {
		t.Fatalf("ATTACHING attachment advanced or wrote desired state: CAS=%d desired=%d", store.casCalls, hosts.desiredWrites)
	}

	for index := range fleet.instances {
		fleet.instances[index].Attachments[0].State = "ATTACHED"
	}
	if err := controller.Tick(context.Background()); err != nil {
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
	intent := validIntent(oci.RegionGRU)
	store := newPlacementMemoryStore(intent)
	store.members[permanentMember(oci.RegionGRU)] = VersionedMemberState{
		State:    testMemberState(intent, Seat{MemberID: "permanent-a", Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}, StageServing),
		Revision: 1,
	}
	store.members[elasticMember(oci.RegionGRU)] = VersionedMemberState{
		State:    testMemberState(intent, Seat{MemberID: "elastic-gru", Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic}, StageServing),
		Revision: 1,
	}
	instances := attachedInstances(intent)
	instances = instances[1:] // permanent-a has disappeared from the owned OCI view.
	fleet := &placementTestFleet{instances: instances}
	hosts := &placementTestHosts{statuses: admittedStatuses(intent)}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, hosts, func(reason string) { holds = append(holds, reason) })

	if err := controller.Tick(context.Background()); err != nil {
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

func startTestPlacementController(t *testing.T, store Store, fleet oci.Fleet, hosts HostView, onHold func(string)) *Controller {
	t.Helper()
	controller, err := StartController(context.Background(), Config{
		Cell: "gru", Region: oci.RegionGRU, FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		ManagedOwner: "owner-a", FleetGeneration: 1, Environment: "production", MemberRole: "terrabase",
		Resources: Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 32 << 30}, OnHold: onHold,
	}, store, placementTestFencer{}, fleet, hosts)
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func newPlacementMemoryStore(intent Intent) *placementMemoryStore {
	store := &placementMemoryStore{intents: []Intent{intent}, members: make(map[string]VersionedMemberState)}
	for _, seat := range []Seat{
		{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent},
		{MemberID: elasticMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic},
	} {
		store.members[seat.MemberID] = VersionedMemberState{State: testMemberState(intent, seat, StageAwaitingRuntimeContract), Revision: 1}
	}
	return store
}

func testMemberState(intent Intent, seat Seat, stage MemberStage) MemberState {
	attempt := uint64(1)
	state := MemberState{
		SchemaVersion: placementSchemaVersion, DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
		MemberID: seat.MemberID, Region: seat.Region, FailureDomain: seat.FailureDomain, Kind: seat.Kind,
		Stage: stage, CreateKey: hostCreateKey(intent, seat, attempt), HostAttempt: attempt,
		HostNode: "node-" + seat.MemberID, InstanceID: "instance-" + seat.MemberID,
		InstanceETag: "etag-1", VolumeID: "volume-" + seat.MemberID,
		AttachmentID: "attachment-" + seat.MemberID, HostGeneration: 1,
		IntentGeneration: intent.Generation, DesiredGeneration: 1,
		OperationID: memberOperationID(intent, seat.MemberID, attempt, "test"), UpdatedAt: time.Now().UTC(),
	}
	if stage == StagePreparedHost || stage == StageAwaitingHost {
		state.HostGeneration = 0
	}
	return state
}

func attachedInstances(intent Intent) []oci.Instance {
	seats := []Seat{
		{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent},
		{MemberID: elasticMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic},
	}
	instances := make([]oci.Instance, 0, len(seats))
	for _, seat := range seats {
		state := testMemberState(intent, seat, StageAwaitingRuntimeContract)
		instances = append(instances, oci.Instance{
			ID: state.InstanceID, Node: state.HostNode, CreateKey: state.CreateKey, Region: seat.Region,
			FaultDomain: seat.FailureDomain, ETag: state.InstanceETag, State: "RUNNING",
			Attachments: []oci.Attachment{{ID: state.AttachmentID, VolumeID: state.VolumeID, InstanceID: state.InstanceID, ETag: "attachment-etag", State: "ATTACHED"}},
		})
	}
	return instances
}

func admittedStatuses(intent Intent) []host.HostStatus {
	statuses := make([]host.HostStatus, 0, 2)
	for index, seat := range []Seat{
		{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent},
		{MemberID: elasticMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic},
	} {
		state := testMemberState(intent, seat, StageAwaitingRuntimeContract)
		statuses = append(statuses, host.HostStatus{Verified: true, SessionExpiresAt: time.Now().Add(time.Minute), Registration: host.Registration{
			Cell: "gru", Node: state.HostNode, FailureDomain: seat.FailureDomain, Environment: "production",
			Roles: []string{"terrabase"}, Generation: 1,
			Capacity: host.Capacity{CPU: 4, MemoryBytes: 8 << 30, DiskBytes: 128 << 30},
			ManagedOCI: &host.ManagedOCIBinding{Region: string(oci.RegionGRU), InstanceID: state.InstanceID,
				Owner: "owner-a", FleetGeneration: 1, CreateKey: state.CreateKey},
		}})
		_ = index
	}
	return statuses
}

type placementMemoryStore struct {
	intents  []Intent
	members  map[string]VersionedMemberState
	casCalls int
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

func (store *placementMemoryStore) CompareAndSwap(_ context.Context, expected uint64, state MemberState) (uint64, error) {
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
	return authority.Snapshot{CandidateID: "controller-a", OwnerID: "owner-a", Leader: true, Ready: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}
}

func (placementTestFencer) Guard(context.Context, uint64) error { return nil }

type placementTestHosts struct {
	statuses      []host.HostStatus
	desiredWrites int
}

func (hosts *placementTestHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	return slices.Clone(hosts.statuses), nil
}

// These methods are intentionally extra methods: the controller's HostView is
// read-only, and the hold test verifies that no hidden desired writer is used.
func (hosts *placementTestHosts) ListDesired(context.Context, string) ([]host.Desired, error) {
	return nil, nil
}

func (hosts *placementTestHosts) ApplyDesired(context.Context, host.Desired) (host.Receipt, error) {
	hosts.desiredWrites++
	return host.Receipt{}, nil
}

type placementTestFleet struct {
	instances      []oci.Instance
	ensureCalls    int
	volumeCalls    int
	attachCalls    int
	cordonCalls    int
	terminateCalls int
}

func (fleet *placementTestFleet) Region() oci.Region { return oci.RegionGRU }
func (fleet *placementTestFleet) Observe(context.Context) ([]oci.Instance, error) {
	return slices.Clone(fleet.instances), nil
}
func (fleet *placementTestFleet) EnsureHost(context.Context, oci.EnsureRequest) (oci.Instance, error) {
	fleet.ensureCalls++
	return oci.Instance{}, errors.New("unexpected EnsureHost")
}
func (fleet *placementTestFleet) CreateRetainedVolume(context.Context, oci.VolumeCreateRequest) (oci.RetainedVolume, error) {
	fleet.volumeCalls++
	return oci.RetainedVolume{}, errors.New("unexpected CreateRetainedVolume")
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
