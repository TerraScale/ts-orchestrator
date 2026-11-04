package placement

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

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
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", CandidateID: "0000000000GR3712FB1A87M2H7", OwnerID: "00000000004AS2NC5H2SW57SZG", Leader: true, Ready: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}
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
