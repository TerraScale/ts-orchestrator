package app

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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
	onObserve func()
}

func (fleet *managedEnrollmentFleet) Observe(context.Context) ([]oci.Instance, error) {
	fleet.calls++
	if fleet.onObserve != nil {
		fleet.onObserve()
	}
	return fleet.instances, fleet.err
}

func TestManagedRegistrationVerifierUsesExactCurrentPins(t *testing.T) {
	fixture := newManagedEnrollmentFixture(t)
	if err := fixture.verifier.VerifyManagedRegistration(t.Context(), fixture.registration); err != nil {
		t.Fatalf("verify current managed registration: %v", err)
	}
	if fixture.intents.calls != 2 || fixture.intents.database != fixture.registration.ManagedPlacement.DatabaseID ||
		fixture.intents.partition != fixture.registration.ManagedPlacement.PartitionID {
		t.Fatalf("authority lookup was not exact: %+v", fixture.intents)
	}
	if fixture.members.calls != 2 || fixture.members.database != fixture.intents.database ||
		fixture.members.partition != fixture.intents.partition || fixture.members.seat != fixture.registration.ManagedPlacement.SeatID {
		t.Fatalf("member lookup was not exact: %+v", fixture.members)
	}
	if fixture.fleet.calls != 1 {
		t.Fatalf("fresh fleet observations = %d, want 1", fixture.fleet.calls)
	}
}

func TestManagedRegistrationRejectsAuthorityChangesDuringOCIObservation(t *testing.T) {
	for _, change := range []string{"intent", "seat"} {
		t.Run(change, func(t *testing.T) {
			fixture := newManagedEnrollmentFixture(t)
			fixture.fleet.onObserve = func() {
				if change == "intent" {
					fixture.intents.entry.Sequence++
				} else {
					fixture.members.member.Revision++
					fixture.members.member.State.HostAttempt++
				}
			}
			if err := fixture.verifier.VerifyManagedRegistration(t.Context(), fixture.registration); err == nil {
				t.Fatal("managed registration survived an authority change during the OCI wait")
			}
		})
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

func fixtureManagedNativeAuthority(cell, environment string) managedNativeAdmissionAuthority {
	return func(ctx context.Context, requestedCell, requestedEnvironment string) error {
		if requestedCell != cell || requestedEnvironment != environment {
			return errors.New("fixture native lineage differs from the independent cell and environment")
		}
		return ctx.Err()
	}
}

func TestManagedNativeAdmissionIsSeparateFromRegistrationProvenance(t *testing.T) {
	fixture := newManagedEnrollmentFixture(t)
	verifier := fixture.verifier.(managedRegistrationVerifier)
	registration := fixture.registration
	desired := host.Desired{Cell: registration.Cell, Node: registration.Node, Role: "terrabase", Environment: registration.Environment,
		ManagedMember: &host.ManagedMemberLaunch{Member: *registration.ManagedMember, OCI: *registration.ManagedOCI}}
	if err := verifier.VerifyManagedNativeAdmission(t.Context(), desired, registration); err != nil {
		t.Fatal(err)
	}
	denied := errors.New("current schema3 lineage refuses native admission")
	verifier.nativeAuthority = func(context.Context, string, string) error { return denied }
	if err := verifier.VerifyManagedNativeAdmission(t.Context(), desired, registration); !errors.Is(err, denied) {
		t.Fatalf("native lineage refusal was bypassed: %v", err)
	}
	if err := verifier.VerifyManagedRegistration(t.Context(), registration); err != nil {
		t.Fatalf("native exclusion blocked common registration/stop provenance: %v", err)
	}
	verifier.nativeAuthority = nil
	if err := verifier.VerifyManagedNativeAdmission(t.Context(), desired, registration); err == nil {
		t.Fatal("missing native policy admitted a native writer")
	}
	if _, err := newManagedRegistrationVerifier("gru", oci.RegionGRU, "regional-owner", 1, fixture.intents, fixture.members, fixture.fleet, nil); err == nil {
		t.Fatal("constructor accepted a missing mandatory native policy")
	}
	for _, mutate := range []func(*host.Desired){
		func(d *host.Desired) { d.Cell = "sfo" },
		func(d *host.Desired) { d.Environment = "canary" },
		func(d *host.Desired) { d.Node = "foreign-node" },
		func(d *host.Desired) { d.Role = "ts-auth" },
		func(d *host.Desired) { d.Withdrawn = true },
		func(d *host.Desired) { d.ManagedMember = nil },
		func(d *host.Desired) {
			member := *d.ManagedMember
			member.Member.HostAttempt++
			d.ManagedMember = &member
		},
		func(d *host.Desired) {
			member := *d.ManagedMember
			member.OCI.InstanceID = "foreign-instance"
			d.ManagedMember = &member
		},
	} {
		changed := desired
		mutate(&changed)
		verifier.nativeAuthority = fixtureManagedNativeAuthority("gru", "production")
		if err := verifier.VerifyManagedNativeAdmission(t.Context(), changed, registration); err == nil {
			t.Fatal("native policy accepted a substituted target")
		}
	}
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
		ID: "ocid1.instance.oc1..node-a", Node: "node-a", CreateKey: "0000000000RW49ETSDPDJTBD4J", Region: oci.RegionGRU,
		PrivateIP:  "10.0.0.11",
		Generation: 1, Owner: "regional-owner", FaultDomain: row.FailureDomain,
		Shape: profile.Compute.Shape, WholeOCPUs: profile.Compute.WholeOCPUs,
		MemoryInGBs: profile.Compute.MemoryInGBs, PlacementProfileDigest: profileDigest,
		PlacementGeneration: committed.Generation, ETag: "etag-a", State: "RUNNING",
	}
	state := placement.MemberState{
		SchemaVersion: 5, DatabaseID: committed.DatabaseID, PartitionID: committed.PartitionID,
		MemberID: row.SeatID, Region: oci.RegionGRU, FailureDomain: row.FailureDomain,
		Kind: placement.MemberPermanent, Stage: placement.StageAwaitingHost, CreateKey: instance.CreateKey,
		HostNode: instance.Node, InstanceID: instance.ID, HostAttempt: 1,
		IntentGeneration: committed.Generation, IntentPayloadDigest: committed.PayloadDigest(),
		ManagedHostProfile: profile, ManagedHostProfileDigest: profileDigest,
		CanonicalRosterRow: row, CanonicalRosterDigest: rosterDigest,
		AuthorityReference: committed.CanonicalRoster.Authority, OperationID: "0000000000XKSKB83V4DB22823", UpdatedAt: time.Now().UTC(),
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
	verifier, err := newManagedRegistrationVerifier("gru", oci.RegionGRU, "regional-owner", 1, intents, members, fleet,
		fixtureManagedNativeAuthority("gru", "production"))
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
