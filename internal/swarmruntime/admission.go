package swarmruntime

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/moby/swarmkit/v2/api"
)

// AdmitNode is called by a manager with verified membership mapped to a node
// certificate identity. Agent description labels never grant placement roles.
func AdmitNode(ctx context.Context, client api.ControlClient, nodeID string, admitted Admission) (*api.Node, error) {
	if nodeID == "" || !catalog.IsOCIRegion(admitted.Region) ||
		!intentName.MatchString(admitted.HostID) && !entityid.Valid(admitted.HostID) || admitted.InstanceID == "" {
		return nil, errors.New("node requires verified membership identity and region")
	}
	if admitted.Role != "manager" && admitted.Role != "container" && admitted.Role != "wasm" {
		return nil, errors.New("invalid admitted host role")
	}
	response, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
	if err != nil {
		return nil, err
	}
	node := response.Node
	if node.Description == nil || node.Description.Hostname != admitted.HostID || (node.Role == api.NodeRoleManager) != (admitted.Role == "manager") {
		return nil, errors.New("node does not match admitted host or certificate role")
	}
	spec := node.Spec.Copy()
	scope := "platform"
	if admitted.Role == "wasm" {
		scope = "tenant"
	}
	if spec.Annotations.Labels == nil {
		spec.Annotations.Labels = map[string]string{}
	}
	if existing := spec.Annotations.Labels[LabelInstanceID]; existing != "" && (existing != admitted.InstanceID || spec.Annotations.Name != admitted.HostID || spec.Annotations.Labels[LabelRegion] != admitted.Region || spec.Annotations.Labels[LabelHostRole] != admitted.Role) {
		return nil, errors.New("admitted node identity or role cannot change")
	}
	if spec.Membership == api.NodeMembershipAccepted && spec.Annotations.Name == admitted.HostID && spec.Annotations.Labels[LabelRegion] == admitted.Region && spec.Annotations.Labels[LabelHostRole] == admitted.Role && spec.Annotations.Labels[LabelInstanceID] == admitted.InstanceID && spec.Annotations.Labels[LabelExecutionScope] == scope {
		return node, nil
	}
	spec.Annotations.Name = admitted.HostID
	spec.Membership = api.NodeMembershipAccepted
	spec.Annotations.Labels[LabelRegion] = admitted.Region
	spec.Annotations.Labels[LabelHostRole] = admitted.Role
	spec.Annotations.Labels[LabelInstanceID] = admitted.InstanceID
	spec.Annotations.Labels[LabelExecutionScope] = scope
	updated, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID, NodeVersion: &node.Meta.Version, Spec: spec})
	if err != nil {
		return nil, err
	}
	return updated.Node, nil
}
