package swarmruntime

import (
	"context"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/moby/swarmkit/v2/api"
)

// Called by the signed worker scenario after real placement and slot exhaustion.
func testFunctionCapacityManagerIntegration(t *testing.T, ctx context.Context, client api.ControlClient, intent FunctionServiceIntent, current *functionIntentFixture, worker release.VerifiedContainer, nodeID string) {
	t.Helper()
	observed, err := intent.PendingCapacity(ctx, client, current, worker)
	if err != nil || observed.Architecture != intent.Architecture || observed.Slots != 0 {
		t.Fatalf("assigned worker requested additional capacity: %+v %v", observed, err)
	}
	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
	if err != nil {
		t.Fatal(err)
	}
	spec := node.Node.Spec.Copy()
	spec.Availability = api.NodeAvailabilityDrain
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: nodeID, NodeVersion: &node.Node.Meta.Version, Spec: spec}); err != nil {
		t.Fatal(err)
	}
	serviceEventually(t, ctx, func() bool {
		observed, err := intent.PendingCapacity(ctx, client, current, worker)
		return err == nil && observed.Architecture == intent.Architecture && observed.Slots == 1
	})
	current.revoked = true
	if _, err := intent.PendingCapacity(ctx, client, current, worker); err == nil {
		t.Fatal("revoked function intent requested capacity")
	}
	current.revoked = false
	node, err = client.GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
	if err != nil {
		t.Fatal(err)
	}
	spec = node.Node.Spec.Copy()
	spec.Availability = api.NodeAvailabilityActive
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: nodeID, NodeVersion: &node.Node.Meta.Version, Spec: spec}); err != nil {
		t.Fatal(err)
	}
	serviceEventually(t, ctx, func() bool {
		observed, err := intent.PendingCapacity(ctx, client, current, worker)
		return err == nil && observed.Slots == 0
	})
}
