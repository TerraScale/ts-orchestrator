package app

import (
	"context"
	"errors"
	"fmt"
	"net"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

type placementIntentLookup interface {
	ReadPlacementIntent(context.Context, string, string) (authority.LogEntry, error)
}

type managedHostObserver interface {
	Observe(context.Context) ([]oci.Instance, error)
}

type managedRegistrationVerifier struct {
	cell            string
	region          oci.Region
	owner           string
	fleetGeneration uint64
	intents         placementIntentLookup
	members         placement.MemberPinReader
	fleet           managedHostObserver
}

func newManagedRegistrationVerifier(
	cell string,
	region oci.Region,
	owner string,
	fleetGeneration uint64,
	intents placementIntentLookup,
	members placement.MemberPinReader,
	fleet managedHostObserver,
) (host.ManagedRegistrationVerifier, error) {
	if cell == "" || region == "" || owner == "" || fleetGeneration == 0 ||
		intents == nil || members == nil || fleet == nil {
		return nil, errors.New("managed registration verifier requires cell, region-bound authority, member store and OCI observer")
	}
	return managedRegistrationVerifier{
		cell: cell, region: region, owner: owner, fleetGeneration: fleetGeneration,
		intents: intents, members: members, fleet: fleet,
	}, nil
}

func (verifier managedRegistrationVerifier) VerifyManagedRegistration(ctx context.Context, registration host.Registration) error {
	if ctx == nil || verifier.intents == nil || verifier.members == nil || verifier.fleet == nil ||
		registration.ManagedPlacement == nil || registration.ManagedMember == nil || registration.ManagedOCI == nil {
		return errors.New("managed registration verifier is not configured for a complete managed registration")
	}
	placementBinding := *registration.ManagedPlacement
	entry, err := verifier.intents.ReadPlacementIntent(ctx, placementBinding.DatabaseID, placementBinding.PartitionID)
	if err != nil {
		return fmt.Errorf("read current placement intent: %w", err)
	}
	if entry.Kind != authority.MutationPlacementIntent || entry.SubjectKey != placementBinding.DatabaseID+"."+placementBinding.PartitionID ||
		entry.Sequence == 0 || entry.Epoch == 0 || len(entry.Payload) == 0 || len(entry.Payload) > maxPlacementIntentBytes {
		return errors.New("current placement log entry is invalid")
	}
	intent, err := placement.DecodeCommittedIntent(entry.Payload)
	if err != nil {
		return fmt.Errorf("decode current placement intent: %w", err)
	}
	if err := intent.ValidateForAdmission(); err != nil || intent.DatabaseID != placementBinding.DatabaseID ||
		intent.PartitionID != placementBinding.PartitionID || intent.OperationID() != entry.OperationID ||
		!intentSelectsCell(intent, verifier.cell) {
		return errors.New("current placement intent does not authorize this managed host")
	}
	if intent.Generation != placementBinding.IntentGeneration || intent.PayloadDigest() != placementBinding.IntentPayloadDigest {
		return errors.New("managed host registration placement generation or payload is stale")
	}
	profile, err := intent.ManagedHostProfile(verifier.region)
	if err != nil {
		return fmt.Errorf("read current regional managed host profile: %w", err)
	}
	profileDigest, err := profile.ProfileDigest()
	if err != nil {
		return fmt.Errorf("verify current regional managed host profile: %w", err)
	}
	rosterDigest, err := intent.CanonicalRosterDigest()
	if err != nil {
		return fmt.Errorf("verify current canonical roster: %w", err)
	}
	if rosterDigest != placementBinding.CanonicalRosterDigest || profileDigest != placementBinding.ManagedHostProfileDigest {
		return errors.New("managed host registration roster or profile digest is stale")
	}

	memberBinding := *registration.ManagedMember
	versioned, err := verifier.members.ReadMember(ctx, placementBinding.DatabaseID, placementBinding.PartitionID, placementBinding.SeatID)
	if err != nil {
		return fmt.Errorf("read exact current placement seat: %w", err)
	}
	state := versioned.State
	if versioned.Revision == 0 || state.Validate() != nil || state.DatabaseID != placementBinding.DatabaseID ||
		state.PartitionID != placementBinding.PartitionID || state.MemberID != placementBinding.SeatID ||
		state.Region != verifier.region || state.HostNode == "" || state.HostNode != registration.Node ||
		state.InstanceID == "" || state.HostAttempt != memberBinding.HostAttempt ||
		state.IntentGeneration != intent.Generation || state.IntentPayloadDigest != intent.PayloadDigest() ||
		state.CanonicalRosterDigest != rosterDigest || state.ManagedHostProfile != profile ||
		state.ManagedHostProfileDigest != profileDigest || state.AuthorityReference != intent.CanonicalRoster.Authority ||
		!managedRegistrationStage(state.Stage) {
		return errors.New("durable placement seat is stale, held, or differs from the managed registration")
	}
	row, ok := rosterRowForSeat(intent, verifier.region, placementBinding.SeatID)
	if !ok || row.FailureDomain != registration.FailureDomain || row != state.CanonicalRosterRow ||
		state.FailureDomain != row.FailureDomain {
		return errors.New("managed registration does not match the exact signed roster seat")
	}
	expectedScope := host.MemberScope{
		ClusterID: intent.CanonicalRoster.ClusterID, TenantID: intent.CanonicalRoster.TenantID,
		DatabaseID: intent.CanonicalRoster.DatabaseID, ShardID: intent.CanonicalRoster.ShardID,
		MemberID: row.MemberID, Incarnation: row.Incarnation,
	}
	if memberBinding.Scope != expectedScope {
		return errors.New("managed registration canonical member scope is stale")
	}
	if placementBinding != (host.ManagedPlacementBinding{
		DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID, SeatID: row.SeatID,
		IntentGeneration: intent.Generation, IntentPayloadDigest: intent.PayloadDigest(),
		CanonicalRosterDigest: rosterDigest, ManagedHostProfileDigest: profileDigest,
	}) {
		return errors.New("managed registration differs from current placement intent")
	}

	// Verify only the hosts that can match this seat: a fleet-wide scan does
	// not fit the registration deadline under the OCI rate limit.
	var observed []oci.Instance
	if selective, ok := verifier.fleet.(oci.SelectiveObserver); ok {
		observed, err = selective.ObserveSelected(ctx, func(id, node string) bool {
			return id == state.InstanceID || node == state.HostNode
		})
	} else {
		observed, err = verifier.fleet.Observe(ctx)
	}
	if err != nil {
		return fmt.Errorf("observe current managed OCI fleet: %w", err)
	}
	var instance oci.Instance
	foundInstance := false
	for _, candidate := range observed {
		if candidate.ID != state.InstanceID && candidate.Node != state.HostNode {
			continue
		}
		if foundInstance {
			return errors.New("OCI observation contains an ambiguous managed host identity")
		}
		instance = candidate
		foundInstance = true
	}
	compute := profile.Compute
	privateIP, _, addressErr := net.SplitHostPort(state.RuntimeManifest.ReplicationListenAddress)
	if instance.ID != state.InstanceID || instance.Node != state.HostNode || instance.CreateKey != state.CreateKey ||
		addressErr != nil || privateIP == "" || instance.PrivateIP != privateIP ||
		instance.Region != verifier.region || instance.Owner != verifier.owner || instance.Generation != verifier.fleetGeneration ||
		instance.FaultDomain != row.FailureDomain || instance.Shape != compute.Shape ||
		instance.WholeOCPUs != compute.WholeOCPUs || instance.MemoryInGBs != compute.MemoryInGBs ||
		instance.PlacementProfileDigest != profileDigest || instance.PlacementGeneration != intent.Generation {
		return errors.New("current OCI host observation differs from the durable placement seat")
	}
	pins := host.ManagedRegistrationPins{
		Placement: placementBinding, Member: memberBinding,
		OCI: host.ManagedOCIBinding{
			Region: string(instance.Region), InstanceID: instance.ID, Owner: instance.Owner,
			FleetGeneration: instance.Generation, CreateKey: instance.CreateKey,
		},
		FailureDomain: row.FailureDomain, AllocatableMemoryBytes: profile.AllocatableMemoryBytes,
		SystemReserveBytes: profile.SystemReserveBytes,
	}
	return host.ValidateManagedRegistrationPins(registration, pins)
}

func managedRegistrationStage(stage placement.MemberStage) bool {
	switch stage {
	case placement.StageAwaitingHost, placement.StagePreparedVolume, placement.StagePreparedAttach,
		placement.StageAwaitingAttach, placement.StagePreparedDesired, placement.StageAwaitingRuntimeContract,
		placement.StageAwaitingHealthy, placement.StageServing, placement.StageCordoned,
		placement.StageDraining, placement.StageDrained:
		return true
	default:
		return false
	}
}

func rosterRowForSeat(intent placement.Intent, region oci.Region, seatID string) (placement.CanonicalRosterRow, bool) {
	for _, row := range intent.CanonicalRoster.Rows {
		if row.Region == region && row.SeatID == seatID {
			return row, true
		}
	}
	return placement.CanonicalRosterRow{}, false
}
