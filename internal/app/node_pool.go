package app

import (
	"context"
	"errors"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// The tags the node pool launches each instance with.
const (
	poolTagCell  = "ts-cell"
	poolTagRole  = "ts-role"
	poolNodeRole = "node"
	// firstPoolNode is the lowest pool node number; 1 to 3 are the quorum nodes.
	firstPoolNode = 4
)

// nodePoolMembers is what enrollment needs from the cell's node pool.
type nodePoolMembers interface {
	Observe(ctx context.Context) (nodescale.PoolState, error)
}

// newNodePool binds the cell's instance pool in the leader's own compartment,
// read from OCI through this instance's principal.
func newNodePool(ctx context.Context, cell string) (*nodescale.OCIPool, error) {
	ociRegion, err := oci.Region(strings.ToUpper(cell)).OCIRegion()
	if err != nil {
		return nil, err
	}
	factory, err := ociclient.InstancePrincipal(ociRegion)
	if err != nil {
		return nil, err
	}
	instanceID, err := hostenroll.ReadInstanceID(ctx, hostenroll.NewIMDSClient())
	if err != nil {
		return nil, err
	}
	compute, err := factory.Compute()
	if err != nil {
		return nil, err
	}
	response, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(instanceID)})
	if err != nil {
		return nil, err
	}
	if response.Instance.CompartmentId == nil {
		return nil, errors.New("leader instance has no compartment")
	}
	return nodescale.NewOCIPool(factory, cell, *response.Instance.CompartmentId)
}
