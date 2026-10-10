package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// The tags the node pool launches each instance with.
const (
	poolTagCell  = "ts-cell"
	poolTagRole  = "ts-role"
	poolNodeRole = "node"
)

// The metadata a pool node copies from its leader. The controller slot and
// bootstrap keys are never copied, so a pool node runs only the host agent.
const poolSSHKeysKey = "ssh_authorized_keys"

// nodePoolMembers is what enrollment needs from the cell's node pool.
type nodePoolMembers interface {
	Observe(ctx context.Context) (nodescale.PoolState, error)
}

// newNodePool binds the cell's instance pool in the leader's own compartment,
// read from OCI through this instance's principal. The factory reads the
// recipe the pool launches from.
func newNodePool(ctx context.Context, cell string) (*nodescale.OCIPool, *ociclient.Factory, error) {
	ociRegion, err := oci.Region(strings.ToUpper(cell)).OCIRegion()
	if err != nil {
		return nil, nil, err
	}
	factory, err := ociclient.InstancePrincipal(ociRegion)
	if err != nil {
		return nil, nil, err
	}
	instanceID, err := hostenroll.ReadInstanceID(ctx, hostenroll.NewIMDSClient())
	if err != nil {
		return nil, nil, err
	}
	compute, err := factory.Compute()
	if err != nil {
		return nil, nil, err
	}
	response, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(instanceID)})
	if err != nil {
		return nil, nil, err
	}
	if response.Instance.CompartmentId == nil {
		return nil, nil, errors.New("leader instance has no compartment")
	}
	pool, err := nodescale.NewOCIPool(factory, cell, *response.Instance.CompartmentId)
	return pool, factory, err
}

// nodeRecipe reads the recipe pool nodes launch from this leader's own
// instance: its compartment, image, shape, subnet and network security groups,
// the availability domains of the tenancy, and its SSH keys and host enrollment bundle.
func nodeRecipe(ctx context.Context, factory *ociclient.Factory, cell string) (nodescale.Recipe, error) {
	instanceID, err := hostenroll.ReadInstanceID(ctx, hostenroll.NewIMDSClient())
	if err != nil {
		return nodescale.Recipe{}, err
	}
	compute, err := factory.Compute()
	if err != nil {
		return nodescale.Recipe{}, err
	}
	response, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(instanceID)})
	if err != nil {
		return nodescale.Recipe{}, err
	}
	attachments, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
		CompartmentId: response.Instance.CompartmentId, InstanceId: new(instanceID)})
	if err != nil {
		return nodescale.Recipe{}, err
	}
	network, err := factory.Network()
	if err != nil {
		return nodescale.Recipe{}, err
	}
	primary, err := primaryVnic(ctx, network, attachments.Items)
	if err != nil {
		return nodescale.Recipe{}, err
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil {
		return nodescale.Recipe{}, err
	}
	identities, err := factory.Identity()
	if err != nil {
		return nodescale.Recipe{}, err
	}
	domains, err := identities.ListAvailabilityDomains(ctx, identity.ListAvailabilityDomainsRequest{CompartmentId: new(tenancy)})
	if err != nil {
		return nodescale.Recipe{}, err
	}
	var names []string
	for _, domain := range domains.Items {
		if domain.Name != nil {
			names = append(names, *domain.Name)
		}
	}
	slices.Sort(names)
	return poolRecipe(cell, response.Instance, primary, names)
}

// primaryVnic returns the VNIC the instance boots on.
func primaryVnic(ctx context.Context, network core.VirtualNetworkClient, attachments []core.VnicAttachment) (core.Vnic, error) {
	for _, attachment := range attachments {
		if attachment.VnicId == nil {
			continue
		}
		response, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachment.VnicId})
		if err != nil {
			return core.Vnic{}, err
		}
		if response.Vnic.IsPrimary != nil && *response.Vnic.IsPrimary {
			return response.Vnic, nil
		}
	}
	return core.Vnic{}, errors.New("leader instance has no primary VNIC")
}

// poolRecipe builds the recipe from the leader's instance, its primary VNIC
// and the sorted availability domains. A missing piece is an error.
func poolRecipe(cell string, instance core.Instance, vnic core.Vnic, domains []string) (nodescale.Recipe, error) {
	image, ok := instance.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !ok || image.ImageId == nil || instance.ShapeConfig == nil || instance.ShapeConfig.Ocpus == nil ||
		instance.ShapeConfig.MemoryInGBs == nil || instance.CompartmentId == nil || vnic.SubnetId == nil {
		return nodescale.Recipe{}, errors.New("leader instance has no image, shape, compartment or subnet")
	}
	metadata := map[string]string{hostboot.NodePoolMetadataKey: `{"schemaVersion":1}`}
	for _, key := range []string{poolSSHKeysKey, hostboot.EnrollmentMetadataKey} {
		value, ok := instance.Metadata[key]
		if !ok {
			return nodescale.Recipe{}, fmt.Errorf("leader instance has no %s metadata", key)
		}
		metadata[key] = value
	}
	recipe := nodescale.Recipe{Cell: cell, SubnetID: *vnic.SubnetId,
		NSGIDs: vnic.NsgIds, AvailabilityDomains: domains, ImageID: *image.ImageId,
		OCPUs: *instance.ShapeConfig.Ocpus, MemoryGB: *instance.ShapeConfig.MemoryInGBs, Metadata: metadata}
	if err := recipe.Validate(); err != nil {
		return nodescale.Recipe{}, err
	}
	return recipe, nil
}
