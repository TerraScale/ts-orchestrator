package executionleader

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

// ServiceAuthorizerConfig belongs to the root manager. Every reader opens its
// actual durable source there; the ordinary producer supplies no reader or seal.
type ServiceAuthorizerConfig struct {
	Client            api.ControlClient
	Authority         *authority.Reader
	Members           placement.MemberPinReader
	Delivery          *delivery.Service
	Roots             trust.Keyring
	Evidence          func(context.Context, string) (io.ReadCloser, error)
	Allocations       execution.ContainerAllocationResolver
	Guard             func(context.Context, uint64) error
	Cell, Environment string
}

type ServiceAuthorizer struct{ config ServiceAuthorizerConfig }

func NewServiceAuthorizer(config ServiceAuthorizerConfig) (*ServiceAuthorizer, error) {
	if config.Client == nil || config.Authority == nil || config.Members == nil || config.Delivery == nil || len(config.Roots) == 0 ||
		config.Evidence == nil || config.Allocations == nil || config.Guard == nil || !release.ValidRegion(strings.ToUpper(config.Cell)) ||
		config.Cell != strings.ToLower(config.Cell) || config.Environment == "" {
		return nil, execution.ErrUnsafe
	}
	keys := make(trust.Keyring, len(config.Roots))
	for id, key := range config.Roots {
		keys[id] = slices.Clone(key)
	}
	config.Roots = keys
	return &ServiceAuthorizer{config: config}, nil
}

// AuthorizeStatefulService authenticates scheduling, independently of the later
// per-task volume, writer and execution-effect admission. Labels only locate
// durable records; the complete spec must equal the root-derived canonical one.
func (a *ServiceAuthorizer) AuthorizeStatefulService(ctx context.Context, requested *api.ServiceSpec) error {
	if a == nil || ctx == nil || ctx.Err() != nil || requested == nil {
		return execution.ErrUnsafe
	}
	c := a.config
	labels := requested.Annotations.Labels
	db, partition, seat := labels["terrascale.database-id"], labels["terrascale.partition-id"], labels["terrascale.member-id"]
	if labels["terrascale.stateful"] != "true" || labels["terrascale.role"] != "terrabase" || labels["terrascale.environment"] != c.Environment ||
		!entityid.Valid(db) || !entityid.Valid(partition) || !entityid.Valid(seat) || !entityid.Valid(labels["terrascale.operation-id"]) {
		return execution.ErrUnsafe
	}
	intent, err := c.Delivery.ContainerIntent(ctx, labels["terrascale.operation-id"])
	if err != nil {
		return err
	}
	if intent.Container == nil || intent.Role != "terrabase" || intent.Cell != c.Cell || intent.Environment != c.Environment {
		return execution.ErrUnsafe
	}
	if err := c.Guard(ctx, intent.AuthorityEpoch); err != nil {
		return err
	}
	if _, err := c.Authority.ReadTerminalIntent(ctx, db, partition); !errors.Is(err, authority.ErrNotFound) {
		return errors.Join(execution.ErrUnsafe, err)
	}
	admitted, err := c.Authority.ReadPlacementIntent(ctx, db, partition)
	if err != nil {
		return err
	}
	placementIntent, err := placement.DecodeCommittedIntent(admitted.Payload)
	if err != nil {
		return err
	}
	member, err := c.Members.ReadMember(ctx, db, partition, seat)
	if err != nil {
		return err
	}
	state := member.State
	if member.Revision == 0 || state.Validate() != nil || state.DatabaseID != db || state.PartitionID != partition || state.MemberID != seat ||
		state.Region != oci.Region(strings.ToUpper(c.Cell)) || state.IntentGeneration != placementIntent.Generation || state.IntentPayloadDigest != placementIntent.PayloadDigest() ||
		state.Stage != placement.StageServing && state.Stage != placement.StageAwaitingHealthy {
		return execution.ErrUnsafe
	}
	row, err := placementIntent.RosterRowForSeat(placement.Seat{MemberID: state.MemberID, Region: state.Region, FailureDomain: state.FailureDomain, Kind: state.Kind})
	if err != nil || row != state.CanonicalRosterRow {
		return errors.Join(execution.ErrUnsafe, err)
	}
	rosterDigest, err := placementIntent.CanonicalRosterDigest()
	if err != nil || rosterDigest != state.CanonicalRosterDigest {
		return errors.Join(execution.ErrUnsafe, err)
	}
	registered, err := c.Authority.ReadHostMutation(ctx, authority.MutationRegistration, c.Cell+"."+state.HostNode)
	if err != nil {
		return err
	}
	var registration host.Registration
	if err := protocol.DecodeStrict(registered.Payload, &registration, 64<<10); err != nil {
		return err
	}
	if _, err := c.Authority.ReadHostMutation(ctx, authority.MutationRetirement, c.Cell+"."+state.HostNode); !errors.Is(err, authority.ErrNotFound) {
		return errors.Join(execution.ErrUnsafe, err)
	}
	if registration.Cell != c.Cell || registration.Environment != c.Environment || registration.Node != state.HostNode ||
		registration.Generation != state.HostGeneration || registration.ManagedOCI == nil || registration.ManagedPlacement == nil || registration.ManagedMember == nil ||
		registration.ManagedOCI.InstanceID != state.InstanceID || registration.ManagedOCI.CreateKey != state.CreateKey ||
		registration.ManagedPlacement.DatabaseID != db || registration.ManagedPlacement.PartitionID != partition || registration.ManagedPlacement.SeatID != seat ||
		registration.ManagedPlacement.IntentGeneration != state.IntentGeneration || registration.ManagedPlacement.IntentPayloadDigest != state.IntentPayloadDigest ||
		registration.ManagedMember.HostAttempt != state.HostAttempt || registration.ManagedMember.Scope.MemberID != row.MemberID || registration.ManagedMember.Scope.Incarnation != row.Incarnation {
		return execution.ErrUnsafe
	}
	envelope, err := trust.DecodeEnvelope(intent.Container.Claim)
	if err != nil {
		return err
	}
	var claim release.ContainerClaim
	if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
		return err
	}
	target := release.ContainerTarget{Cell: strings.ToUpper(c.Cell), Environment: c.Environment, Role: "terrabase", Architecture: claim.Architecture}
	allocations, err := c.Allocations(ctx, *intent.Container, c.Roots, target)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	qualified, err := execution.VerifyStatefulDeclared(ctx, *intent.Container, c.Roots, target, now, now.Add(15*time.Second), c.Evidence, allocations)
	if err != nil {
		return err
	}
	manifest := state.EffectiveRuntimeManifest()
	data := qualified.Data()
	if data.DatabaseID != db || data.PartitionID != partition || data.VolumeID != state.VolumeID || data.FileSystemUUID != manifest.FileSystemUUID ||
		data.FileSystemType != manifest.FileSystemType {
		return execution.ErrUnsafe
	}
	uid, gid, err := qualifiedUser(ctx, *intent.Container, c.Roots, target, c.Evidence, allocations)
	if err != nil {
		return err
	}
	nodes, err := c.Client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return err
	}
	if nodes == nil {
		return execution.ErrUnsafe
	}
	region, err := state.Region.OCIRegion()
	if err != nil {
		return err
	}
	var node *api.Node
	for _, candidate := range nodes.Nodes {
		if candidate != nil && candidate.Spec.Annotations.Name == registration.ID {
			if node != nil {
				return execution.ErrUnsafe
			}
			node = candidate
		}
	}
	if node == nil || node.Spec.Membership != api.NodeMembershipAccepted || node.Spec.Availability != api.NodeAvailabilityActive ||
		node.Spec.Annotations.Labels["terrascale.region"] != region || node.Spec.Annotations.Labels["terrascale.instance-id"] != state.InstanceID ||
		node.Spec.Annotations.Labels["terrascale.host-role"] != "container" || node.Spec.Annotations.Labels["terrascale.execution-scope"] != "platform" ||
		node.Description == nil || node.Description.Resources == nil {
		return execution.ErrUnsafe
	}
	expected, err := memberServiceSpec(intent, state, node.ID, qualified.Container().Claim(), uid, gid, registration, node.Description.Resources)
	if err != nil || !proto.Equal(expected, requested) {
		return errors.Join(execution.ErrUnsafe, err)
	}
	latestPlacement, err := c.Authority.ReadPlacementIntent(ctx, db, partition)
	if err != nil || latestPlacement.Sequence != admitted.Sequence {
		return errors.Join(execution.ErrUnsafe, err)
	}
	latestMember, err := c.Members.ReadMember(ctx, db, partition, seat)
	if err != nil || latestMember.Revision != member.Revision {
		return errors.Join(execution.ErrUnsafe, err)
	}
	latestRegistration, err := c.Authority.ReadHostMutation(ctx, authority.MutationRegistration, c.Cell+"."+state.HostNode)
	if err != nil || latestRegistration.Sequence != registered.Sequence {
		return errors.Join(execution.ErrUnsafe, err)
	}
	confirmed, err := c.Delivery.ContainerIntent(ctx, intent.OperationID)
	if err != nil {
		return err
	}
	before, err := json.Marshal(intent, json.Deterministic(true))
	if err != nil {
		return err
	}
	after, err := json.Marshal(confirmed, json.Deterministic(true))
	if err != nil || !slices.Equal(before, after) {
		return errors.Join(execution.ErrUnsafe, err)
	}
	if _, err := c.Authority.ReadTerminalIntent(ctx, db, partition); !errors.Is(err, authority.ErrNotFound) {
		return errors.Join(execution.ErrUnsafe, err)
	}
	if _, err := c.Authority.ReadHostMutation(ctx, authority.MutationRetirement, c.Cell+"."+state.HostNode); !errors.Is(err, authority.ErrNotFound) {
		return errors.Join(execution.ErrUnsafe, err)
	}
	currentNode, err := c.Client.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID})
	if err != nil || currentNode == nil || currentNode.Node == nil || !proto.Equal(&currentNode.Node.Spec, &node.Spec) ||
		!proto.Equal(currentNode.Node.Description, node.Description) || !time.Now().Before(qualified.ValidUntil()) {
		return errors.Join(execution.ErrUnsafe, err)
	}
	return c.Guard(ctx, intent.AuthorityEpoch)
}
