package executionleader

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
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
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
)

// memberServiceSpec is shared by production creation and grant verification.
// One immutable member owns one replica, one exact accepted node and stop-first
// update/rollback. The stateless ServiceIntent's stateful refusal stays intact.
func memberServiceSpec(intent delivery.Intent, state placement.MemberState, nodeID string, claim release.ContainerClaim, uid, gid uint32, registration host.Registration, available *api.Resources) (*api.ServiceSpec, error) {
	if intent.Container == nil || state.Validate() != nil || nodeID == "" || uid == 0 || gid == 0 || registration.ManagedMember == nil || registration.ManagedPlacement == nil || available == nil || available.NanoCPUs < 10_000_000 || available.NanoCPUs > int64(registration.Capacity.CPU)*1_000_000_000 {
		return nil, execution.ErrUnsafe
	}
	wire, err := (&api.ContainerSpec{Image: claim.Image, User: strconv.FormatUint(uint64(uid), 10) + ":" + strconv.FormatUint(uint64(gid), 10)}).Marshal()
	if err != nil {
		return nil, err
	}
	region, err := state.Region.OCIRegion()
	if err != nil {
		return nil, err
	}
	memory := state.ManagedHostProfile.CgroupMemoryMaxBytes
	if memory == 0 || memory > uint64(^uint64(0)>>1) || registration.Capacity.CPU < 1 {
		return nil, execution.ErrUnsafe
	}
	identity := entityid.Derive("stateful-service", intent.Environment, intent.Cell, state.DatabaseID, state.PartitionID, state.MemberID)
	labels := map[string]string{"terrascale.stateful": "true", "terrascale.role": "terrabase", "terrascale.intent-id": identity, "terrascale.operation-id": intent.OperationID, "terrascale.region": region, "terrascale.environment": intent.Environment, "terrascale.database-id": state.DatabaseID, "terrascale.partition-id": state.PartitionID, "terrascale.member-id": state.MemberID, "terrascale.placement-sha256": state.IntentPayloadDigest}
	sum := sha256.Sum256([]byte(identity))
	resources := &api.Resources{NanoCPUs: available.NanoCPUs, MemoryBytes: int64(memory)}
	return &api.ServiceSpec{Annotations: api.Annotations{Name: fmt.Sprintf("ts-db-%x", sum[:16]), Labels: labels}, Task: api.TaskSpec{Runtime: &api.TaskSpec_Generic{Generic: &api.GenericRuntimeSpec{Kind: execution.StatefulContainerKind, Payload: &types.Any{TypeUrl: execution.StatefulContainerTypeURL, Value: wire}}}, Resources: &api.ResourceRequirements{Limits: resources, Reservations: resources.Copy()}, Restart: &api.RestartPolicy{Condition: api.RestartOnAny, Delay: types.DurationProto(5 * time.Second)}, Placement: &api.Placement{Constraints: []string{"node.id==" + nodeID}, Platforms: []*api.Platform{{OS: "linux", Architecture: claim.Architecture}}}}, Mode: &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 1}}, Update: &api.UpdateConfig{Parallelism: 1, FailureAction: api.UpdateConfig_PAUSE, Monitor: types.DurationProto(30 * time.Second), Order: api.UpdateConfig_STOP_FIRST}, Rollback: &api.UpdateConfig{Parallelism: 1, FailureAction: api.UpdateConfig_PAUSE, Monitor: types.DurationProto(30 * time.Second), Order: api.UpdateConfig_STOP_FIRST}}, nil
}

// Apply creates per-member services from authenticated delivery and placement.
// Resolve repeats every mapping before a worker can execute the resulting task.
func (p *Producer) Apply(ctx context.Context, requested delivery.Intent) error {
	if p == nil || requested.Container == nil || requested.Role != "terrabase" {
		return execution.ErrUnsafe
	}
	intent, err := p.releases.ContainerIntent(ctx, requested.OperationID)
	if err != nil {
		return err
	}
	a, err := intent.Fingerprint()
	if err != nil {
		return err
	}
	b, err := requested.Fingerprint()
	if err != nil || a != b {
		return execution.ErrUnsafe
	}
	if err := p.authority.Guard(ctx, intent.AuthorityEpoch); err != nil {
		return err
	}
	envelope, err := trust.DecodeEnvelope(intent.Container.Claim)
	if err != nil {
		return err
	}
	var claim release.ContainerClaim
	if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
		return err
	}
	target := release.ContainerTarget{Cell: string(oci.Region(claim.Cell)), Environment: p.environment, Role: "terrabase", Architecture: claim.Architecture}
	allocations, err := p.allocations(ctx, *intent.Container, p.roots, target)
	if err != nil {
		return err
	}
	uid, gid, err := qualifiedUser(ctx, *intent.Container, p.roots, target, p.open, allocations)
	if err != nil {
		return err
	}
	declared, err := execution.VerifyStatefulDeclared(ctx, *intent.Container, p.roots, target, time.Now().UTC(), time.Now().UTC().Add(15*time.Second), p.open, allocations)
	if err != nil {
		return err
	}
	placements, err := p.members.ListIntents(ctx)
	if err != nil {
		return err
	}
	count := 0
	for _, placementIntent := range placements {
		if _, err := p.authority.ReadTerminalIntent(ctx, placementIntent.DatabaseID, placementIntent.PartitionID); err == nil {
			continue
		} else if !errors.Is(err, authority.ErrNotFound) {
			return err
		}
		members, err := p.members.ListMembers(ctx, placementIntent.DatabaseID, placementIntent.PartitionID)
		if err != nil {
			return err
		}
		for _, member := range members {
			state := member.State
			if state.DatabaseID != declared.Data().DatabaseID || state.PartitionID != declared.Data().PartitionID || state.VolumeID != declared.Data().VolumeID {
				continue
			}
			if state.Region != oci.Region(claim.Cell) || state.Stage != placement.StageServing && state.Stage != placement.StageAwaitingHealthy {
				continue
			}
			registered, err := p.authority.ReadHostMutation(ctx, authority.MutationRegistration, p.cell+"."+state.HostNode)
			if err != nil {
				return err
			}
			var registration host.Registration
			if err := protocol.DecodeStrict(registered.Payload, &registration, 64<<10); err != nil {
				return err
			}
			nodes, err := p.control.ListNodes(ctx, &api.ListNodesRequest{})
			if err != nil {
				return err
			}
			nodeID := ""
			var available *api.Resources
			if nodes == nil {
				return execution.ErrUnsafe
			}
			for _, node := range nodes.Nodes {
				if node == nil {
					return execution.ErrUnsafe
				}
				if node.Spec.Membership == api.NodeMembershipAccepted && node.Spec.Annotations.Name == registration.ID && node.Spec.Annotations.Labels["terrascale.instance-id"] == state.InstanceID && node.Spec.Annotations.Labels["terrascale.host-role"] == "container" {
					if nodeID != "" {
						return execution.ErrUnsafe
					}
					if node.Description == nil || node.Description.Resources == nil {
						return execution.ErrUnsafe
					}
					nodeID = node.ID
					available = node.Description.Resources
				}
			}
			if nodeID == "" {
				return execution.ErrUnsafe
			}
			spec, err := memberServiceSpec(intent, state, nodeID, claim, uid, gid, registration, available)
			if err != nil {
				return err
			}
			services, err := p.control.ListServices(ctx, &api.ListServicesRequest{})
			if err != nil {
				return err
			}
			var existing *api.Service
			if services == nil {
				return execution.ErrUnsafe
			}
			for _, service := range services.Services {
				if service == nil {
					return execution.ErrUnsafe
				}
				if service.Spec.Annotations.Name == spec.Annotations.Name {
					if existing != nil {
						return execution.ErrUnsafe
					}
					existing = service
				}
			}
			if err := p.authority.Guard(ctx, intent.AuthorityEpoch); err != nil {
				return err
			}
			if existing == nil {
				_, err = p.control.CreateService(ctx, &api.CreateServiceRequest{Spec: spec})
			} else if !proto.Equal(&existing.Spec, spec) {
				for _, key := range []string{"terrascale.intent-id", "terrascale.database-id", "terrascale.partition-id", "terrascale.member-id"} {
					if existing.Spec.Annotations.Labels[key] != spec.Annotations.Labels[key] {
						return execution.ErrUnsafe
					}
				}
				_, err = p.control.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: existing.ID, ServiceVersion: &existing.Meta.Version, Spec: spec})
			}
			if err != nil {
				return err
			}
			count++
		}
	}
	if count == 0 {
		return fmt.Errorf("%w: no admitted retained member services", execution.ErrUnsafe)
	}
	return p.authority.Guard(ctx, intent.AuthorityEpoch)
}
