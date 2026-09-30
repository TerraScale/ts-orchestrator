package app

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestManagedRegistrationRetainsDrainReconciliationStages(t *testing.T) {
	for _, stage := range []placement.MemberStage{
		placement.StageServing, placement.StageCordoned, placement.StageDraining, placement.StageDrained,
	} {
		if !managedRegistrationStage(stage) {
			t.Fatalf("current managed host was rejected during %s", stage)
		}
	}
	for _, stage := range []placement.MemberStage{
		placement.StageRemoveCandidate, placement.StageStorageHandled, placement.StageTerminated, placement.StageRemoved,
	} {
		if managedRegistrationStage(stage) {
			t.Fatalf("managed host was admitted outside its active drain window: %s", stage)
		}
	}
}

type managedEnrollmentIntentReader struct {
	entry     authority.LogEntry
	err       error
	calls     int
	database  string
	partition string
}

func (reader *managedEnrollmentIntentReader) ReadPlacementIntent(_ context.Context, databaseID, partitionID string) (authority.LogEntry, error) {
	reader.calls++
	reader.database = databaseID
	reader.partition = partitionID
	return reader.entry, reader.err
}

type managedEnrollmentMemberReader struct {
	member    placement.VersionedMemberState
	err       error
	calls     int
	database  string
	partition string
	seat      string
}

func (reader *managedEnrollmentMemberReader) ReadMember(_ context.Context, databaseID, partitionID, seatID string) (placement.VersionedMemberState, error) {
	reader.calls++
	reader.database = databaseID
	reader.partition = partitionID
	reader.seat = seatID
	return reader.member, reader.err
}

type managedEnrollmentFleet struct {
	instances []oci.Instance
	err       error
	calls     int
}

func (fleet *managedEnrollmentFleet) Observe(context.Context) ([]oci.Instance, error) {
	fleet.calls++
	return fleet.instances, fleet.err
}

func TestManagedRegistrationVerifierUsesExactCurrentPins(t *testing.T) {
	fixture := newManagedEnrollmentFixture(t)
	if err := fixture.verifier.VerifyManagedRegistration(t.Context(), fixture.registration); err != nil {
		t.Fatalf("verify current managed registration: %v", err)
	}
	if fixture.intents.calls != 1 || fixture.intents.database != fixture.registration.ManagedPlacement.DatabaseID ||
		fixture.intents.partition != fixture.registration.ManagedPlacement.PartitionID {
		t.Fatalf("authority lookup was not exact: %+v", fixture.intents)
	}
	if fixture.members.calls != 1 || fixture.members.database != fixture.intents.database ||
		fixture.members.partition != fixture.intents.partition || fixture.members.seat != fixture.registration.ManagedPlacement.SeatID {
		t.Fatalf("member lookup was not exact: %+v", fixture.members)
	}
	if fixture.fleet.calls != 1 {
		t.Fatalf("fresh fleet observations = %d, want 1", fixture.fleet.calls)
	}
}

func TestManagedRegistrationVerifierRejectsStaleAndMismatchedPins(t *testing.T) {
	checks := []struct {
		name   string
		change func(*managedEnrollmentFixture)
	}{
		{name: "intent payload digest", change: func(fixture *managedEnrollmentFixture) {
			fixture.registration.ManagedPlacement.IntentPayloadDigest = fmt.Sprintf("%064x", 12)
		}},
		{name: "canonical roster digest", change: func(fixture *managedEnrollmentFixture) {
			fixture.registration.ManagedPlacement.CanonicalRosterDigest = fmt.Sprintf("%064x", 12)
		}},
		{name: "profile digest", change: func(fixture *managedEnrollmentFixture) {
			fixture.registration.ManagedPlacement.ManagedHostProfileDigest = fmt.Sprintf("%064x", 12)
		}},
		{name: "superseded member attempt", change: func(fixture *managedEnrollmentFixture) {
			fixture.members.member.State.HostAttempt++
		}},
		{name: "replacement hold", change: func(fixture *managedEnrollmentFixture) {
			fixture.members.member.State.Stage = placement.StageRemoveCandidate
		}},
		{name: "member node", change: func(fixture *managedEnrollmentFixture) {
			fixture.registration.Node = "node-b"
		}},
		{name: "canonical member scope", change: func(fixture *managedEnrollmentFixture) {
			fixture.registration.ManagedMember.Scope.Incarnation = fmt.Sprintf("%032x", 99)
		}},
		{name: "OCI owner", change: func(fixture *managedEnrollmentFixture) {
			fixture.fleet.instances[0].Owner = "other-owner"
		}},
		{name: "OCI compute shape", change: func(fixture *managedEnrollmentFixture) {
			fixture.fleet.instances[0].Shape = "other-shape"
		}},
		{name: "OCI placement generation", change: func(fixture *managedEnrollmentFixture) {
			fixture.fleet.instances[0].PlacementGeneration++
		}},
		{name: "ambiguous OCI node", change: func(fixture *managedEnrollmentFixture) {
			fixture.fleet.instances = append(fixture.fleet.instances, oci.Instance{Node: fixture.registration.Node})
		}},
		{name: "allocatable memory", change: func(fixture *managedEnrollmentFixture) {
			fixture.registration.Capacity.MemoryBytes += 4096
		}},
		{name: "reserve", change: func(fixture *managedEnrollmentFixture) {
			fixture.registration.SystemReserveBytes += 4096
		}},
		{name: "OCI observation error", change: func(fixture *managedEnrollmentFixture) {
			fixture.fleet.err = errors.New("provider unavailable")
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			fixture := newManagedEnrollmentFixture(t)
			check.change(&fixture)
			if err := fixture.verifier.VerifyManagedRegistration(t.Context(), fixture.registration); err == nil {
				t.Fatal("mismatched managed registration was accepted")
			}
		})
	}
}

func TestManagedRegistrationVerifierDoesNotFallbackFromExactReaders(t *testing.T) {
	fixture := newManagedEnrollmentFixture(t)
	fixture.intents.err = authority.ErrNotFound
	if err := fixture.verifier.VerifyManagedRegistration(t.Context(), fixture.registration); err == nil {
		t.Fatal("missing exact placement intent was accepted")
	}
	if fixture.intents.calls != 1 || fixture.members.calls != 0 || fixture.fleet.calls != 0 {
		t.Fatalf("missing exact intent triggered fallback reads: authority=%d member=%d fleet=%d", fixture.intents.calls, fixture.members.calls, fixture.fleet.calls)
	}

	fixture = newManagedEnrollmentFixture(t)
	fixture.members.err = placement.ErrMemberNotFound
	if err := fixture.verifier.VerifyManagedRegistration(t.Context(), fixture.registration); err == nil {
		t.Fatal("missing exact placement seat was accepted")
	}
	if fixture.members.calls != 1 || fixture.fleet.calls != 0 {
		t.Fatalf("missing exact member triggered fallback: member=%d fleet=%d", fixture.members.calls, fixture.fleet.calls)
	}
}

type managedEnrollmentFixture struct {
	verifier     host.ManagedRegistrationVerifier
	registration host.Registration
	intents      *managedEnrollmentIntentReader
	members      *managedEnrollmentMemberReader
	fleet        *managedEnrollmentFleet
}

func newManagedEnrollmentFixture(t *testing.T) managedEnrollmentFixture {
	t.Helper()
	intent := testManagedPlacementIntent()
	payload, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := placement.DecodeCommittedIntent(payload)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := committed.ManagedHostProfile(oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := profile.ProfileDigest()
	if err != nil {
		t.Fatal(err)
	}
	rosterDigest, err := committed.CanonicalRosterDigest()
	if err != nil {
		t.Fatal(err)
	}
	row := committed.CanonicalRoster.Rows[0]
	instance := oci.Instance{
		ID: "ocid1.instance.oc1..node-a", Node: "node-a", CreateKey: "host-create-a", Region: oci.RegionGRU,
		PrivateIP:  "10.0.0.11",
		Generation: 1, Owner: "regional-owner", FaultDomain: row.FailureDomain,
		Shape: profile.Compute.Shape, WholeOCPUs: profile.Compute.WholeOCPUs,
		MemoryInGBs: profile.Compute.MemoryInGBs, PlacementProfileDigest: profileDigest,
		PlacementGeneration: committed.Generation, ETag: "etag-a", State: "RUNNING",
	}
	state := placement.MemberState{
		SchemaVersion: 4, DatabaseID: committed.DatabaseID, PartitionID: committed.PartitionID,
		MemberID: row.SeatID, Region: oci.RegionGRU, FailureDomain: row.FailureDomain,
		Kind: placement.MemberPermanent, Stage: placement.StageAwaitingHost, CreateKey: instance.CreateKey,
		HostNode: instance.Node, InstanceID: instance.ID, HostAttempt: 1,
		IntentGeneration: committed.Generation, IntentPayloadDigest: committed.PayloadDigest(),
		ManagedHostProfile: profile, ManagedHostProfileDigest: profileDigest,
		CanonicalRosterRow: row, CanonicalRosterDigest: rosterDigest,
		AuthorityReference: committed.CanonicalRoster.Authority, OperationID: "prepare-a", UpdatedAt: time.Now().UTC(),
	}
	state.RuntimeManifest = committed.RuntimeManifests[0]
	state.RuntimeManifestDigest, err = state.RuntimeManifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("fixture member state: %v", err)
	}
	intents := &managedEnrollmentIntentReader{entry: authority.LogEntry{
		Kind: authority.MutationPlacementIntent, SubjectKey: committed.DatabaseID + "." + committed.PartitionID,
		OperationID: committed.OperationID(), Epoch: 3, Sequence: 7, Payload: payload,
	}}
	members := &managedEnrollmentMemberReader{member: placement.VersionedMemberState{State: state, Revision: 4}}
	fleet := &managedEnrollmentFleet{instances: []oci.Instance{instance}}
	verifier, err := newManagedRegistrationVerifier("gru", oci.RegionGRU, "regional-owner", 1, intents, members, fleet)
	if err != nil {
		t.Fatal(err)
	}
	scope := host.MemberScope{
		ClusterID: committed.CanonicalRoster.ClusterID, TenantID: committed.CanonicalRoster.TenantID,
		DatabaseID: committed.CanonicalRoster.DatabaseID, ShardID: committed.CanonicalRoster.ShardID,
		MemberID: row.MemberID, Incarnation: row.Incarnation,
	}
	hostNKey, _ := testNKey(t)
	registration := host.Registration{
		Cell: "gru", Node: instance.Node, FailureDomain: row.FailureDomain, Environment: "production",
		Roles: []string{"terrabase"}, PublicKey: "unused", NATSUserPublicKey: hostNKey, Generation: 1,
		Capacity: host.Capacity{MemoryBytes: int64(profile.AllocatableMemoryBytes)},
		ManagedPlacement: &host.ManagedPlacementBinding{
			DatabaseID: committed.DatabaseID, PartitionID: committed.PartitionID, SeatID: row.SeatID,
			IntentGeneration: committed.Generation, IntentPayloadDigest: committed.PayloadDigest(),
			CanonicalRosterDigest: rosterDigest, ManagedHostProfileDigest: profileDigest,
		},
		ManagedOCI: &host.ManagedOCIBinding{
			Region: string(instance.Region), InstanceID: instance.ID, Owner: instance.Owner,
			FleetGeneration: instance.Generation, CreateKey: instance.CreateKey,
		},
		ManagedMember:      &host.ManagedMemberBinding{Scope: scope, HostAttempt: state.HostAttempt},
		SystemReserveBytes: int64(profile.SystemReserveBytes),
	}
	return managedEnrollmentFixture{verifier: verifier, registration: registration, intents: intents, members: members, fleet: fleet}
}
