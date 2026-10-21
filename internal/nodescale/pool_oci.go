package nodescale

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Ownership tags separate each cell's capacity pools and their resources.
const (
	tagCell         = "ts-cell"
	tagRole         = "ts-role"
	tagNode         = "ts-node"
	tagPool         = "ts-pool"
	tagCapacityRole = "ts-capacity-role"
	tagArchitecture = "ts-architecture"
	tagShape        = "ts-shape"
	tagOperationID  = "ts-operation-id"
	tagRecipeSHA256 = "ts-recipe-sha256"

	roleNodePool   = "node-pool"
	roleNodeConfig = "node-config"
	roleNode       = "node"
)

// computeManagementAPI is the instance pool and configuration surface. core.ComputeManagementClient implements it.
type computeManagementAPI interface {
	ListInstancePools(ctx context.Context, request core.ListInstancePoolsRequest) (core.ListInstancePoolsResponse, error)
	GetInstancePool(ctx context.Context, request core.GetInstancePoolRequest) (core.GetInstancePoolResponse, error)
	ListInstancePoolInstances(ctx context.Context, request core.ListInstancePoolInstancesRequest) (core.ListInstancePoolInstancesResponse, error)
	ListInstanceConfigurations(ctx context.Context, request core.ListInstanceConfigurationsRequest) (core.ListInstanceConfigurationsResponse, error)
	GetInstanceConfiguration(ctx context.Context, request core.GetInstanceConfigurationRequest) (core.GetInstanceConfigurationResponse, error)
}

// computeAPI is the instance surface. core.ComputeClient implements it.
type computeAPI interface {
	ListShapes(ctx context.Context, request core.ListShapesRequest) (core.ListShapesResponse, error)
	GetInstance(ctx context.Context, request core.GetInstanceRequest) (core.GetInstanceResponse, error)
	ListVnicAttachments(ctx context.Context, request core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error)
}

// networkAPI is the VNIC surface. core.VirtualNetworkClient implements it.
type networkAPI interface {
	GetVnic(ctx context.Context, request core.GetVnicRequest) (core.GetVnicResponse, error)
}

// OCIPool observes regional OCI pools. Root lifecycle operations own every mutation.
type OCIPool struct {
	management    computeManagementAPI
	compute       computeAPI
	network       networkAPI
	cell          string
	capacity      Capacity
	compartmentID string
}

// NewOCIPool binds one cell's capacity pool to the factory's OCI clients.
func NewOCIPool(factory *ociclient.Factory, cell, compartmentID string, capacity Capacity) (*OCIPool, error) {
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
	return newOCIPool(management, compute, network, cell, compartmentID, capacity)
}

// CompartmentID is the authenticated pool scope used by home spending admission.
func (o *OCIPool) CompartmentID() string { return o.compartmentID }

func newOCIPool(management computeManagementAPI, compute computeAPI, network networkAPI, cell, compartmentID string, capacity Capacity) (*OCIPool, error) {
	if !cellPattern.MatchString(cell) || compartmentID == "" {
		return nil, fmt.Errorf("node pool for cell %q needs a cell name and a compartment", cell)
	}
	if err := capacity.Validate(); err != nil {
		return nil, err
	}
	return &OCIPool{management: management, compute: compute, network: network,
		cell: cell, compartmentID: compartmentID, capacity: capacity}, nil
}

func (o *OCIPool) Observe(ctx context.Context) (PoolState, error) {
	pools, err := listAll(func(page *string) ([]core.InstancePoolSummary, *string, error) {
		response, err := o.management.ListInstancePools(ctx, core.ListInstancePoolsRequest{
			CompartmentId: new(o.compartmentID), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return PoolState{}, fmt.Errorf("list observed node pools: %w", err)
	}
	var state PoolState
	seen := map[string]bool{}
	for _, summary := range pools {
		name := deref(summary.DisplayName)
		legacy := name == "ts-"+o.cell+"-nodes" && summary.FreeformTags[tagCell] == o.cell && summary.FreeformTags[tagRole] == roleNodePool
		capacity := Capacity{Role: summary.FreeformTags[tagCapacityRole], Architecture: summary.FreeformTags[tagArchitecture], Shape: summary.FreeformTags[tagShape]}
		owned := capacity.Validate() == nil && summary.FreeformTags[tagCell] == o.cell && summary.FreeformTags[tagRole] == roleNodePool &&
			name == PoolName(o.cell, capacity) && summary.FreeformTags[tagPool] == name
		if absent(string(summary.LifecycleState)) || !legacy && !owned {
			continue
		}
		if seen[name] {
			return PoolState{}, fmt.Errorf("multiple observed pools named %s; refusing to guess", name)
		}
		seen[name] = true
		response, err := o.management.GetInstancePool(ctx, core.GetInstancePoolRequest{InstancePoolId: summary.Id})
		if err != nil {
			return PoolState{}, fmt.Errorf("read observed pool %s: %w", name, err)
		}
		pool := response.InstancePool
		if deref(pool.Id) != deref(summary.Id) || deref(pool.CompartmentId) != o.compartmentID || deref(pool.DisplayName) != name ||
			pool.FreeformTags[tagCell] != o.cell || pool.FreeformTags[tagRole] != roleNodePool || !legacy &&
			(pool.FreeformTags[tagPool] != name || pool.FreeformTags[tagCapacityRole] != capacity.Role || pool.FreeformTags[tagArchitecture] != capacity.Architecture || pool.FreeformTags[tagShape] != capacity.Shape) {
			return PoolState{}, fmt.Errorf("observed pool %s changed ownership", name)
		}
		if legacy {
			state.Pending = fmt.Sprintf("legacy pool %s (%s, size %d) requires verified migration; capacity is pending", name, deref(pool.Id), deref(pool.Size))
		}
		if len(seen) > 1 {
			state.PoolID, state.ConfigurationID, state.LifecycleState = "", "", ""
		} else {
			state.PoolID, state.ConfigurationID, state.LifecycleState = deref(pool.Id), deref(pool.InstanceConfigurationId), string(pool.LifecycleState)
		}
		state.Exists = true
		state.Size += deref(pool.Size)
		members, err := o.members(ctx, deref(pool.Id))
		if err != nil {
			return PoolState{}, err
		}
		if capacity.Role == RoleWasm && deref(pool.Size) > len(members) {
			state.ProvisioningFunctions = append(state.ProvisioningFunctions, CapacityDemand{Architecture: capacity.Architecture, Slots: uint64(deref(pool.Size) - len(members))})
		}
		for _, member := range members {
			instance, _, err := o.instance(ctx, deref(member.Id))
			if err != nil {
				return PoolState{}, err
			}
			if !absent(string(instance.LifecycleState)) && (instance.InstanceOptions == nil || !deref(instance.InstanceOptions.AreLegacyImdsEndpointsDisabled)) {
				state.Pending = fmt.Sprintf("instance %s has not positively disabled legacy IMDS endpoints", deref(member.Id))
			}
			ip, err := o.privateIP(ctx, deref(member.Id))
			if err != nil {
				return PoolState{}, err
			}
			state.Instances = append(state.Instances, PoolInstance{ID: deref(member.Id), Name: deref(member.DisplayName),
				State: deref(member.State), PrivateIP: ip, AvailabilityDomain: deref(member.AvailabilityDomain),
				FaultDomain: deref(member.FaultDomain), Created: deref(member.TimeCreated).Time, Capacity: capacity,
				PoolID: deref(pool.Id), ConfigurationID: deref(pool.InstanceConfigurationId)})
		}
	}
	slices.SortFunc(state.Instances, func(a, b PoolInstance) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	return state, nil
}

// TargetSize reads the selected pool independently of the region's total size.
func (o *OCIPool) TargetSize(ctx context.Context, recipe Recipe) (int, error) {
	if recipe.Cell != o.cell || recipe.Capacity != o.capacity {
		return 0, fmt.Errorf("selected capacity differs from target pool")
	}
	pool, _, err := o.pool(ctx)
	if err != nil || pool == nil {
		return 0, err
	}
	return deref(pool.Size), nil
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
	if deref(response.CompartmentId) != o.compartmentID || deref(response.DisplayName) != PoolName(o.cell, o.capacity) || !o.owns(response.FreeformTags, roleNodePool) {
		return nil, "", fmt.Errorf("instance pool %s changed ownership", id)
	}
	return &response.InstancePool, deref(response.Etag), nil
}

// poolID finds the cell's pool by name and tags. Two matches are an error, never a guess.
func (o *OCIPool) poolID(ctx context.Context) (string, error) {
	name := PoolName(o.cell, o.capacity)
	pools, err := listAll(func(page *string) ([]core.InstancePoolSummary, *string, error) {
		response, err := o.management.ListInstancePools(ctx, core.ListInstancePoolsRequest{
			CompartmentId: common.String(o.compartmentID), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return "", fmt.Errorf("list instance pools: %w", err)
	}
	var ids []string
	for _, pool := range pools {
		if deref(pool.DisplayName) == "ts-"+o.cell+"-nodes" && pool.FreeformTags[tagCell] == o.cell &&
			pool.FreeformTags[tagRole] == roleNodePool && !absent(string(pool.LifecycleState)) {
			return "", fmt.Errorf("legacy pool %s (%s, size %d) requires verified migration; new capacity is pending", deref(pool.DisplayName), deref(pool.Id), deref(pool.Size))
		}
		if deref(pool.DisplayName) == name && o.owns(pool.FreeformTags, roleNodePool) && !absent(string(pool.LifecycleState)) {
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
func launchDetails(recipe Recipe, compartmentID, operationID string) *core.InstanceConfigurationLaunchInstanceDetails {
	return &core.InstanceConfigurationLaunchInstanceDetails{
		CompartmentId: common.String(compartmentID),
		Shape:         new(recipe.Capacity.Shape),
		ShapeConfig: &core.InstanceConfigurationLaunchInstanceShapeConfigDetails{
			Ocpus: common.Float32(recipe.OCPUs), MemoryInGBs: common.Float32(recipe.MemoryGB)},
		SourceDetails: core.InstanceConfigurationInstanceSourceViaImageDetails{
			ImageId: common.String(recipe.ImageID), BootVolumeSizeInGBs: common.Int64(BootVolumeGB)},
		CreateVnicDetails: &core.InstanceConfigurationCreateVnicDetails{AssignPublicIp: common.Bool(false), NsgIds: recipe.NSGIDs},
		Metadata:          recipe.Metadata,
		InstanceOptions:   &core.InstanceConfigurationInstanceOptions{AreLegacyImdsEndpointsDisabled: new(true)},
		LicensingConfigs:  []core.LaunchInstanceLicensingConfig{},
		FreeformTags:      launchTags(recipe, roleNode, operationID),
	}
}

func launchTags(recipe Recipe, role, operationID string) map[string]string {
	tags := poolTags(recipe.Cell, recipe.Capacity, role)
	tags[tagRecipeSHA256] = recipe.SHA256()
	if operationID != "" {
		tags[tagOperationID] = operationID
	}
	return tags
}

func poolTags(cell string, capacity Capacity, role string) map[string]string {
	return map[string]string{tagCell: cell, tagRole: role, tagPool: PoolName(cell, capacity),
		tagCapacityRole: capacity.Role, tagArchitecture: capacity.Architecture, tagShape: capacity.Shape}
}

func (o *OCIPool) owns(tags map[string]string, role string) bool {
	return tags[tagCell] == o.cell && tags[tagRole] == role && tags[tagPool] == PoolName(o.cell, o.capacity) &&
		tags[tagCapacityRole] == o.capacity.Role && tags[tagArchitecture] == o.capacity.Architecture && tags[tagShape] == o.capacity.Shape
}

// validateImage verifies every placement against OCI's image-specific shape inventory before writing resources.
func (o *OCIPool) validateImage(ctx context.Context, recipe Recipe) error {
	for _, domain := range recipe.AvailabilityDomains {
		shapes, err := listAll(func(page *string) ([]core.Shape, *string, error) {
			response, err := o.compute.ListShapes(ctx, core.ListShapesRequest{
				CompartmentId: new(o.compartmentID), ImageId: new(recipe.ImageID),
				AvailabilityDomain: new(domain), Shape: new(recipe.Capacity.Shape), Page: page})
			return response.Items, response.OpcNextPage, err
		})
		if err != nil {
			return fmt.Errorf("list image %s shapes in %s: %w", recipe.ImageID, domain, err)
		}
		index := slices.IndexFunc(shapes, func(shape core.Shape) bool { return deref(shape.Shape) == recipe.Capacity.Shape })
		if index < 0 {
			return fmt.Errorf("image %s does not support shape %s in %s", recipe.ImageID, recipe.Capacity.Shape, domain)
		}
		shape := shapes[index]
		architecture, err := catalog.ShapeArchitecture(deref(shape.ProcessorDescription))
		if err != nil {
			return fmt.Errorf("shape %s in %s: %w", recipe.Capacity.Shape, domain, err)
		}
		if architecture != recipe.Capacity.Architecture {
			return fmt.Errorf("shape %s in %s has architecture %s, recipe requires %s", recipe.Capacity.Shape, domain, architecture, recipe.Capacity.Architecture)
		}
		if err := ValidateResources(shape, recipe.OCPUs, recipe.MemoryGB); err != nil {
			return fmt.Errorf("pool shape %s in %s: %w", recipe.Capacity.Shape, domain, err)
		}
	}
	return nil
}

// listAll follows OCI's opc-next-page token to the last page.
func listAll[T any](fetch func(page *string) ([]T, *string, error)) ([]T, error) {
	var all []T
	var page *string
	seen := map[string]bool{}
	for {
		items, next, err := fetch(page)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if next == nil || *next == "" {
			return all, nil
		}
		if seen[*next] {
			return nil, fmt.Errorf("OCI listing pagination repeated a page token")
		}
		seen[*next] = true
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

func poolCreateRequestSHA256(request *http.Request) (string, error) {
	defer request.Body.Close()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "%s\n%s\n%s\n%s\n%s\n", request.Method, request.URL.EscapedPath(), request.Header.Get("Content-Type"), request.Header.Get("if-match"), request.Header.Get("opc-retry-token"))
	_, _ = digest.Write(body)
	return hex.EncodeToString(digest.Sum(nil)), nil
}
