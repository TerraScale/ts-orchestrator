package executionleader

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
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
