package nodescale

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// Freeform tags that own a region's pool resources. A resource without the cell's tags is never touched.
const (
	tagCell = "ts-cell"
	tagRole = "ts-role"
	tagNode = "ts-node"

	roleNodePool   = "node-pool"
	roleNodeConfig = "node-config"
	roleNode       = "node"
)

// computeManagementAPI is the instance pool and configuration surface. core.ComputeManagementClient implements it.
type computeManagementAPI interface {
	ListInstancePools(ctx context.Context, request core.ListInstancePoolsRequest) (core.ListInstancePoolsResponse, error)
	GetInstancePool(ctx context.Context, request core.GetInstancePoolRequest) (core.GetInstancePoolResponse, error)
	CreateInstancePool(ctx context.Context, request core.CreateInstancePoolRequest) (core.CreateInstancePoolResponse, error)
	UpdateInstancePool(ctx context.Context, request core.UpdateInstancePoolRequest) (core.UpdateInstancePoolResponse, error)
	ListInstancePoolInstances(ctx context.Context, request core.ListInstancePoolInstancesRequest) (core.ListInstancePoolInstancesResponse, error)
	DetachInstancePoolInstance(ctx context.Context, request core.DetachInstancePoolInstanceRequest) (core.DetachInstancePoolInstanceResponse, error)
	ListInstanceConfigurations(ctx context.Context, request core.ListInstanceConfigurationsRequest) (core.ListInstanceConfigurationsResponse, error)
	CreateInstanceConfiguration(ctx context.Context, request core.CreateInstanceConfigurationRequest) (core.CreateInstanceConfigurationResponse, error)
	DeleteInstanceConfiguration(ctx context.Context, request core.DeleteInstanceConfigurationRequest) (core.DeleteInstanceConfigurationResponse, error)
}

// computeAPI is the instance surface. core.ComputeClient implements it.
type computeAPI interface {
	GetInstance(ctx context.Context, request core.GetInstanceRequest) (core.GetInstanceResponse, error)
	UpdateInstance(ctx context.Context, request core.UpdateInstanceRequest) (core.UpdateInstanceResponse, error)
	ListVnicAttachments(ctx context.Context, request core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error)
}

// networkAPI is the VNIC surface. core.VirtualNetworkClient implements it.
type networkAPI interface {
	GetVnic(ctx context.Context, request core.GetVnicRequest) (core.GetVnicResponse, error)
}

// OCIPool is one region's instance pool in OCI. It finds and owns the pool by name and tags.
type OCIPool struct {
	management    computeManagementAPI
	compute       computeAPI
	network       networkAPI
	cell          string
	compartmentID string
}

// NewOCIPool binds one cell's pool to the factory's OCI clients.
func NewOCIPool(factory *ociclient.Factory, cell, compartmentID string) (*OCIPool, error) {
	management, err := factory.ComputeManagement()
	if err != nil {
		return nil, err
	}
	compute, err := factory.Compute()
	if err != nil {
		return nil, err
	}
	network, err := factory.Network()
	if err != nil {
		return nil, err
	}
	return newOCIPool(management, compute, network, cell, compartmentID)
}

func newOCIPool(management computeManagementAPI, compute computeAPI, network networkAPI, cell, compartmentID string) (*OCIPool, error) {
	if !cellPattern.MatchString(cell) || compartmentID == "" {
		return nil, fmt.Errorf("node pool for cell %q needs a cell name and a compartment", cell)
	}
	return &OCIPool{management: management, compute: compute, network: network,
		cell: cell, compartmentID: compartmentID}, nil
}

func (o *OCIPool) Observe(ctx context.Context) (PoolState, error) {
	pool, _, err := o.pool(ctx)
	if err != nil || pool == nil {
		return PoolState{}, err
	}
	members, err := o.members(ctx, deref(pool.Id))
	if err != nil {
		return PoolState{}, err
	}
	state := PoolState{Exists: true, PoolID: deref(pool.Id), ConfigurationID: deref(pool.InstanceConfigurationId),
		LifecycleState: string(pool.LifecycleState), Size: deref(pool.Size)}
	for _, member := range members {
		ip, err := o.privateIP(ctx, deref(member.Id))
		if err != nil {
			return PoolState{}, err
		}
		state.Instances = append(state.Instances, PoolInstance{ID: deref(member.Id), Name: deref(member.DisplayName),
			State: deref(member.State), PrivateIP: ip, AvailabilityDomain: deref(member.AvailabilityDomain),
			FaultDomain: deref(member.FaultDomain), Created: deref(member.TimeCreated).Time})
	}
	slices.SortFunc(state.Instances, func(a, b PoolInstance) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	return state, nil
}

// Ensure makes the recipe's configuration and the cell's pool exist, and points the pool at the recipe.
// It never changes the pool's size.
func (o *OCIPool) Ensure(ctx context.Context, recipe Recipe) (PoolState, error) {
	if err := recipe.Validate(); err != nil {
		return PoolState{}, err
	}
	if recipe.Cell != o.cell {
		return PoolState{}, fmt.Errorf("recipe for cell %s given to the pool of cell %s", recipe.Cell, o.cell)
	}
	configID, err := o.ensureConfiguration(ctx, recipe)
	if err != nil {
		return PoolState{}, err
	}
	pool, etag, err := o.pool(ctx)
	if err != nil {
		return PoolState{}, err
	}
	// OCI applies a re-point later, so the configuration the pool references now must survive this cycle.
	keep := []string{configID}
	switch {
	case pool == nil:
		err = o.createPool(ctx, recipe, configID)
	case deref(pool.InstanceConfigurationId) != configID || !placementsMatch(pool, recipe):
		keep = append(keep, deref(pool.InstanceConfigurationId))
		err = o.point(ctx, pool, etag, configID, recipe)
	}
	if err != nil {
		return PoolState{}, err
	}
	if err := o.pruneConfigurations(ctx, keep...); err != nil {
		return PoolState{}, err
	}
	return o.Observe(ctx)
}

// Grow raises the pool from size from to from+1. A replay that already reached from+1 is done.
func (o *OCIPool) Grow(ctx context.Context, from int) error {
	if from < 0 || from >= MaxPoolNodes {
		return fmt.Errorf("pool of cell %s cannot grow from %d; it holds 0 to %d nodes", o.cell, from, MaxPoolNodes)
	}
	pool, etag, err := o.pool(ctx)
	if err != nil {
		return err
	}
	if pool == nil {
		return fmt.Errorf("instance pool of cell %s does not exist; ensure it first", o.cell)
	}
	switch size := deref(pool.Size); size {
	case from + 1:
		return nil
	case from:
	default:
		return fmt.Errorf("%w: pool of cell %s is %d, expected %d", ErrPoolChanged, o.cell, size, from)
	}
	_, err = o.management.UpdateInstancePool(ctx, core.UpdateInstancePoolRequest{
		InstancePoolId: pool.Id, IfMatch: common.String(etag),
		UpdateInstancePoolDetails: core.UpdateInstancePoolDetails{Size: common.Int(from + 1)}})
	if err != nil {
		return fmt.Errorf("grow instance pool %s to %d: %w", deref(pool.DisplayName), from+1, err)
	}
	return nil
}

// Name gives a pool instance its node name and keeps its other tags. A named instance is done.
func (o *OCIPool) Name(ctx context.Context, instanceID, node string) error {
	_, member, err := o.memberOf(ctx, instanceID)
	if err != nil {
		return err
	}
	if !member {
		return fmt.Errorf("%w: %s", ErrNotPoolInstance, instanceID)
	}
	instance, etag, err := o.instance(ctx, instanceID)
	if err != nil {
		return err
	}
	if deref(instance.DisplayName) == node && instance.FreeformTags[tagNode] == node {
		return nil
	}
	tags := map[string]string{}
	maps.Copy(tags, instance.FreeformTags)
	tags[tagNode] = node
	_, err = o.compute.UpdateInstance(ctx, core.UpdateInstanceRequest{
		InstanceId: common.String(instanceID), IfMatch: common.String(etag),
		UpdateInstanceDetails: core.UpdateInstanceDetails{DisplayName: common.String(node), FreeformTags: tags}})
	if err != nil {
		return fmt.Errorf("name instance %s %s: %w", instanceID, node, err)
	}
	return nil
}

// Remove takes a pool instance out by detaching it with a size decrement and termination, so OCI never
// picks the victim. An instance already terminated is done.
func (o *OCIPool) Remove(ctx context.Context, instanceID string) error {
	pool, member, err := o.memberOf(ctx, instanceID)
	if err != nil {
		return err
	}
	if member {
		_, err := o.management.DetachInstancePoolInstance(ctx, core.DetachInstancePoolInstanceRequest{
			InstancePoolId: pool.Id,
			DetachInstancePoolInstanceDetails: core.DetachInstancePoolInstanceDetails{InstanceId: common.String(instanceID),
				IsDecrementSize: common.Bool(true), IsAutoTerminate: common.Bool(true)}})
		if err != nil {
			return fmt.Errorf("detach instance %s from pool %s: %w", instanceID, deref(pool.DisplayName), err)
		}
		return nil
	}
	instance, _, err := o.instance(ctx, instanceID)
	if err != nil {
		return err
	}
	if absent(string(instance.LifecycleState)) {
		return nil
	}
	return fmt.Errorf("%w: instance %s is %s", ErrNotPoolInstance, instanceID, instance.LifecycleState)
}

// pool returns the cell's pool and its ETag, or nil when there is none.
func (o *OCIPool) pool(ctx context.Context) (*core.InstancePool, string, error) {
	id, err := o.poolID(ctx)
	if err != nil || id == "" {
		return nil, "", err
	}
	response, err := o.management.GetInstancePool(ctx, core.GetInstancePoolRequest{InstancePoolId: common.String(id)})
	if err != nil {
		return nil, "", fmt.Errorf("get instance pool %s: %w", id, err)
	}
	return &response.InstancePool, deref(response.Etag), nil
}

// poolID finds the cell's pool by name and tags. Two matches are an error, never a guess.
func (o *OCIPool) poolID(ctx context.Context) (string, error) {
	name := PoolName(o.cell)
	pools, err := listAll(func(page *string) ([]core.InstancePoolSummary, *string, error) {
		response, err := o.management.ListInstancePools(ctx, core.ListInstancePoolsRequest{
			CompartmentId: common.String(o.compartmentID), DisplayName: common.String(name), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return "", fmt.Errorf("list instance pools: %w", err)
	}
	var ids []string
	for _, pool := range pools {
		if deref(pool.DisplayName) == name && pool.FreeformTags[tagCell] == o.cell &&
			pool.FreeformTags[tagRole] == roleNodePool && !absent(string(pool.LifecycleState)) {
			ids = append(ids, deref(pool.Id))
		}
	}
	switch len(ids) {
	case 0:
		return "", nil
	case 1:
		return ids[0], nil
	}
	return "", fmt.Errorf("%d instance pools named %s carry cell %s's tags; refusing to guess", len(ids), name, o.cell)
}

// members lists the pool's live instances. Terminated ones are gone and do not count.
func (o *OCIPool) members(ctx context.Context, poolID string) ([]core.InstanceSummary, error) {
	items, err := listAll(func(page *string) ([]core.InstanceSummary, *string, error) {
		response, err := o.management.ListInstancePoolInstances(ctx, core.ListInstancePoolInstancesRequest{
			CompartmentId: common.String(o.compartmentID), InstancePoolId: common.String(poolID), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return nil, fmt.Errorf("list instances of pool %s: %w", poolID, err)
	}
	return slices.DeleteFunc(items, func(item core.InstanceSummary) bool { return absent(deref(item.State)) }), nil
}

// memberOf returns the cell's pool, and whether instanceID is one of its live members.
func (o *OCIPool) memberOf(ctx context.Context, instanceID string) (*core.InstancePool, bool, error) {
	pool, _, err := o.pool(ctx)
	if err != nil || pool == nil {
		return nil, false, err
	}
	members, err := o.members(ctx, deref(pool.Id))
	if err != nil {
		return nil, false, err
	}
	return pool, slices.ContainsFunc(members, func(member core.InstanceSummary) bool {
		return deref(member.Id) == instanceID
	}), nil
}

// privateIP is the primary VNIC's address. It is empty while the instance has no primary VNIC yet.
func (o *OCIPool) privateIP(ctx context.Context, instanceID string) (string, error) {
	attachments, err := listAll(func(page *string) ([]core.VnicAttachment, *string, error) {
		response, err := o.compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
			CompartmentId: common.String(o.compartmentID), InstanceId: common.String(instanceID), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return "", fmt.Errorf("list VNIC attachments of instance %s: %w", instanceID, err)
	}
	for _, attachment := range attachments {
		if attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached || attachment.VnicId == nil {
			continue
		}
		vnic, err := o.network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachment.VnicId})
		if err != nil {
			return "", fmt.Errorf("get VNIC %s of instance %s: %w", *attachment.VnicId, instanceID, err)
		}
		if deref(vnic.IsPrimary) {
			return deref(vnic.PrivateIp), nil
		}
	}
	return "", nil
}

// instance reads one instance and its ETag.
func (o *OCIPool) instance(ctx context.Context, instanceID string) (core.Instance, string, error) {
	response, err := o.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: common.String(instanceID)})
	if err != nil {
		return core.Instance{}, "", fmt.Errorf("get instance %s: %w", instanceID, err)
	}
	return response.Instance, deref(response.Etag), nil
}

// configurations lists the cell's node configurations: the name prefix and the cell tag must both match.
func (o *OCIPool) configurations(ctx context.Context) ([]core.InstanceConfigurationSummary, error) {
	items, err := listAll(func(page *string) ([]core.InstanceConfigurationSummary, *string, error) {
		response, err := o.management.ListInstanceConfigurations(ctx, core.ListInstanceConfigurationsRequest{
			CompartmentId: common.String(o.compartmentID), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return nil, fmt.Errorf("list instance configurations: %w", err)
	}
	return slices.DeleteFunc(items, func(config core.InstanceConfigurationSummary) bool {
		return !strings.HasPrefix(deref(config.DisplayName), configPrefix(o.cell)) || config.FreeformTags[tagCell] != o.cell
	}), nil
}

// ensureConfiguration creates the recipe's configuration unless the cell already has it, and returns its OCID.
func (o *OCIPool) ensureConfiguration(ctx context.Context, recipe Recipe) (string, error) {
	name := ConfigurationName(recipe)
	configs, err := o.configurations(ctx)
	if err != nil {
		return "", err
	}
	if i := slices.IndexFunc(configs, func(config core.InstanceConfigurationSummary) bool {
		return deref(config.DisplayName) == name
	}); i >= 0 {
		return deref(configs[i].Id), nil
	}
	response, err := o.management.CreateInstanceConfiguration(ctx, core.CreateInstanceConfigurationRequest{
		CreateInstanceConfiguration: core.CreateInstanceConfigurationDetails{
			CompartmentId:   common.String(o.compartmentID),
			DisplayName:     common.String(name),
			FreeformTags:    map[string]string{tagCell: o.cell, tagRole: roleNodeConfig},
			InstanceDetails: core.ComputeInstanceDetails{LaunchDetails: launchDetails(recipe, o.compartmentID)},
		},
		OpcRetryToken: retryToken(name),
	})
	if err != nil {
		return "", fmt.Errorf("create instance configuration %s: %w", name, err)
	}
	return deref(response.Id), nil
}

// pruneConfigurations deletes the cell's configurations that are not in keep.
func (o *OCIPool) pruneConfigurations(ctx context.Context, keep ...string) error {
	configs, err := o.configurations(ctx)
	if err != nil {
		return err
	}
	for _, config := range configs {
		if slices.Contains(keep, deref(config.Id)) {
			continue
		}
		if _, err := o.management.DeleteInstanceConfiguration(ctx, core.DeleteInstanceConfigurationRequest{
			InstanceConfigurationId: config.Id}); err != nil {
			return fmt.Errorf("delete instance configuration %s: %w", deref(config.DisplayName), err)
		}
	}
	return nil
}

// createPool makes the cell's pool at size 0, with one placement per availability domain on the recipe's subnet.
func (o *OCIPool) createPool(ctx context.Context, recipe Recipe, configID string) error {
	name := PoolName(o.cell)
	placements := make([]core.CreateInstancePoolPlacementConfigurationDetails, 0, len(recipe.AvailabilityDomains))
	for _, domain := range recipe.AvailabilityDomains {
		placements = append(placements, core.CreateInstancePoolPlacementConfigurationDetails{
			AvailabilityDomain: common.String(domain),
			PrimaryVnicSubnets: &core.InstancePoolPlacementPrimarySubnet{SubnetId: common.String(recipe.SubnetID)},
		})
	}
	_, err := o.management.CreateInstancePool(ctx, core.CreateInstancePoolRequest{
		CreateInstancePoolDetails: core.CreateInstancePoolDetails{
			CompartmentId:           common.String(o.compartmentID),
			InstanceConfigurationId: common.String(configID),
			PlacementConfigurations: placements,
			Size:                    common.Int(0),
			DisplayName:             common.String(name),
			FreeformTags:            map[string]string{tagCell: o.cell, tagRole: roleNodePool},
		},
		OpcRetryToken: retryToken(name),
	})
	if err != nil {
		return fmt.Errorf("create instance pool %s: %w", name, err)
	}
	return nil
}

// point moves the pool to the recipe's configuration and placements. Its size is left alone.
func (o *OCIPool) point(ctx context.Context, pool *core.InstancePool, etag, configID string, recipe Recipe) error {
	details := core.UpdateInstancePoolDetails{InstanceConfigurationId: common.String(configID)}
	if !placementsMatch(pool, recipe) {
		for _, domain := range recipe.AvailabilityDomains {
			details.PlacementConfigurations = append(details.PlacementConfigurations, core.UpdateInstancePoolPlacementConfigurationDetails{
				AvailabilityDomain: common.String(domain),
				PrimaryVnicSubnets: &core.InstancePoolPlacementPrimarySubnet{SubnetId: common.String(recipe.SubnetID)},
			})
		}
	}
	_, err := o.management.UpdateInstancePool(ctx, core.UpdateInstancePoolRequest{
		InstancePoolId: pool.Id, IfMatch: common.String(etag), UpdateInstancePoolDetails: details})
	if err != nil {
		return fmt.Errorf("point instance pool %s at %s: %w", deref(pool.DisplayName), configID, err)
	}
	return nil
}

// placementsMatch reports whether the pool places nodes in the recipe's availability domains, in order, each on its subnet.
func placementsMatch(pool *core.InstancePool, recipe Recipe) bool {
	if len(pool.PlacementConfigurations) != len(recipe.AvailabilityDomains) {
		return false
	}
	for i, placement := range pool.PlacementConfigurations {
		if deref(placement.AvailabilityDomain) != recipe.AvailabilityDomains[i] || placementSubnet(placement) != recipe.SubnetID {
			return false
		}
	}
	return true
}

// placementSubnet is the placement's primary VNIC subnet. OCI may still answer with only the deprecated primarySubnetId.
func placementSubnet(placement core.InstancePoolPlacementConfiguration) string {
	if placement.PrimaryVnicSubnets != nil && placement.PrimaryVnicSubnets.SubnetId != nil {
		return *placement.PrimaryVnicSubnets.SubnetId
	}
	return deref(placement.PrimarySubnetId)
}

// launchDetails is what every pool node launches from. Its subnet comes from the pool's placement.
func launchDetails(recipe Recipe, compartmentID string) *core.InstanceConfigurationLaunchInstanceDetails {
	return &core.InstanceConfigurationLaunchInstanceDetails{
		CompartmentId: common.String(compartmentID),
		Shape:         common.String(NodeShape),
		ShapeConfig: &core.InstanceConfigurationLaunchInstanceShapeConfigDetails{
			Ocpus: common.Float32(recipe.OCPUs), MemoryInGBs: common.Float32(recipe.MemoryGB)},
		SourceDetails: core.InstanceConfigurationInstanceSourceViaImageDetails{
			ImageId: common.String(recipe.ImageID), BootVolumeSizeInGBs: common.Int64(BootVolumeGB)},
		CreateVnicDetails: &core.InstanceConfigurationCreateVnicDetails{AssignPublicIp: common.Bool(false), NsgIds: recipe.NSGIDs},
		Metadata:          recipe.Metadata,
		FreeformTags:      map[string]string{tagCell: recipe.Cell, tagRole: roleNode},
	}
}

// listAll follows OCI's opc-next-page token to the last page.
func listAll[T any](fetch func(page *string) ([]T, *string, error)) ([]T, error) {
	var all []T
	var page *string
	for {
		items, next, err := fetch(page)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if next == nil {
			return all, nil
		}
		page = next
	}
}

// retryToken makes a retried create of name idempotent in OCI.
func retryToken(name string) *string {
	digest := sha256.Sum256([]byte("ts-804:" + name))
	return common.String(hex.EncodeToString(digest[:])[:32])
}

// absent reports a lifecycle state in which the resource is gone.
func absent(state string) bool { return state == "TERMINATED" || state == "TERMINATING" }

// deref returns an optional SDK field's value, or the zero value when it is unset.
func deref[T any](value *T) T {
	var zero T
	if value == nil {
		return zero
	}
	return *value
}
