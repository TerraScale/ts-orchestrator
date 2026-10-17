package nodescale

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
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
	root          *rootoci.Client
	management    computeManagementAPI
	compute       computeAPI
	network       networkAPI
	cell          string
	capacity      Capacity
	compartmentID string
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
	if o.root != nil {
		observed, err := o.CapacityObservation(ctx)
		if err != nil {
			return PoolState{}, err
		}
		return poolState(observed.Pools), nil
	}

	pools, err := listAll(func(page *string) ([]core.InstancePoolSummary, *string, error) {
		response, err := o.management.ListInstancePools(ctx, core.ListInstancePoolsRequest{
			CompartmentId: new(o.compartmentID), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return PoolState{}, fmt.Errorf("list observed node pools: %w", err)
	}
	var observed []rootoci.NodePoolObservation
	memberIDs := map[string]bool{}
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
		if pool.Size == nil || *pool.Size < 0 || *pool.Size > 1024 {
			return PoolState{}, errors.New("observed pool has unknown or excessive size")
		}
		detail := rootoci.NodePoolObservation{ID: deref(pool.Id), Name: name, ConfigurationID: deref(pool.InstanceConfigurationId), LifecycleState: string(pool.LifecycleState), Role: capacity.Role, Architecture: capacity.Architecture, Shape: capacity.Shape, Size: deref(pool.Size), Legacy: legacy}
		configuration, configErr := o.configuration(ctx, detail.ConfigurationID)
		if configErr != nil {
			detail.Pending = append(detail.Pending, configErr.Error())
		} else {
			detail.Configuration = configuration
		}
		members, err := o.members(ctx, deref(pool.Id))
		if err != nil {
			return PoolState{}, err
		}
		for _, member := range members {
			instance, _, err := o.instance(ctx, deref(member.Id))
			if err != nil {
				return PoolState{}, err
			}
			if absent(string(instance.LifecycleState)) {
				continue
			}
			if memberIDs[deref(member.Id)] {
				return PoolState{}, errors.New("observed member appears in multiple pools")
			}
			memberIDs[deref(member.Id)] = true
			if deref(instance.Id) != deref(member.Id) || deref(instance.CompartmentId) != o.compartmentID {
				return PoolState{}, errors.New("observed member differs from the signed worker compartment")
			}
			ip, err := o.privateIP(ctx, deref(member.Id))
			if err != nil {
				return PoolState{}, err
			}
			detail.Members = append(detail.Members, rootoci.NodeMemberObservation{ID: deref(member.Id), Name: deref(instance.DisplayName), State: string(instance.LifecycleState), PrivateIP: ip, AvailabilityDomain: deref(instance.AvailabilityDomain), FaultDomain: deref(instance.FaultDomain), Created: deref(instance.TimeCreated).Time, LegacyIMDSDisabled: memberIMDS(instance.InstanceOptions)})
		}
		if pool.Size != nil && *pool.Size > MaxPoolNodes {
			detail.Pending = append(detail.Pending, "observed pool exceeds the fixed regional node limit")
		}
		observed = append(observed, detail)
		if len(observed) > 128 || len(memberIDs) > 1024 {
			return PoolState{}, errors.New("node pool observation exceeds its aggregate bound")
		}
	}
	slices.SortFunc(observed, func(a, b rootoci.NodePoolObservation) int { return cmp.Compare(a.ID, b.ID) })
	return poolState(observed), nil
}

// TargetSize reads the selected pool independently of the region's total size.
func (o *OCIPool) TargetSize(ctx context.Context, recipe Recipe) (int, error) {
	if o.root != nil {
		if recipe.Cell != o.cell || recipe.Capacity != o.capacity {
			return 0, errors.New("selected capacity differs from target pool")
		}
		observed, err := o.CapacityObservation(ctx)
		if err != nil {
			return 0, err
		}
		target := 0
		for _, pool := range observed.Pools {
			if pool.Legacy {
				return 0, fmt.Errorf("legacy pool %s requires verified migration", pool.Name)
			}
			if pool.Role == recipe.Capacity.Role && pool.Architecture == recipe.Capacity.Architecture && pool.Shape == recipe.Capacity.Shape {
				target = pool.Size
			}
		}
		return target, nil
	}

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
	for range 32 {
		items, next, err := fetch(page)
		if err != nil {
			return nil, err
		}
		if len(items) > 4096-len(all) {
			return nil, errors.New("OCI observation exceeds its item bound")
		}
		all = append(all, items...)
		if next == nil {
			return all, nil
		}
		if *next == "" || len(*next) > 4096 || seen[*next] {
			return nil, errors.New("OCI observation has an invalid or repeated continuation")
		}
		seen[*next] = true
		page = next
	}
	return nil, errors.New("OCI observation exceeds its page bound")
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

// ReadNodePoolCapacity executes only inside the root observation backend.
func ReadNodePoolCapacity(ctx context.Context, factory *ociclient.Factory, cell, compartment string) (PoolState, error) {
	management, err := factory.ComputeManagement()
	if err != nil {
		return PoolState{}, err
	}
	compute, err := factory.Compute()
	if err != nil {
		return PoolState{}, err
	}
	network, err := factory.Network()
	if err != nil {
		return PoolState{}, err
	}
	return (&OCIPool{management: management, compute: compute, network: network, cell: cell, compartmentID: compartment}).Observe(ctx)
}

// NewRootPool retains the lifecycle client and expected scope. The compartment
// only narrows a later root-derived observation; it grants no provider access.
func NewRootPool(client *rootoci.Client, cell, compartment string, capacity Capacity) (*OCIPool, error) {
	if client == nil || !cellPattern.MatchString(cell) || compartment == "" {
		return nil, ErrCapacityPending
	}
	if err := capacity.Validate(); err != nil {
		return nil, err
	}
	return &OCIPool{root: client, cell: cell, compartmentID: compartment, capacity: capacity}, nil
}

func (o *OCIPool) CapacityObservation(ctx context.Context) (rootoci.NodeCapacityObservation, error) {
	if o == nil || o.root == nil {
		return rootoci.NodeCapacityObservation{}, ErrCapacityPending
	}
	observed, err := o.root.ObserveNodeCapacity(ctx)
	if err != nil {
		return rootoci.NodeCapacityObservation{}, err
	}
	if !strings.EqualFold(observed.Cell, o.cell) || observed.WorkerCompartmentID != o.compartmentID || !time.Now().Before(observed.ExpiresAt) {
		return rootoci.NodeCapacityObservation{}, ErrCapacityPending
	}
	return observed, nil
}

func poolState(pools []rootoci.NodePoolObservation) PoolState {
	state := PoolState{Pools: pools}
	var pending []string
	for _, pool := range pools {
		state.Exists = true
		state.Size += pool.Size
		if len(pools) == 1 {
			state.PoolID, state.ConfigurationID, state.LifecycleState = pool.ID, pool.ConfigurationID, pool.LifecycleState
		}
		pending = append(pending, pool.Pending...)
		if pool.Legacy {
			pending = append(pending, fmt.Sprintf("legacy pool %s (%s, size %d) requires verified migration; capacity is pending", pool.Name, pool.ID, pool.Size))
		}
		capacity := Capacity{Role: pool.Role, Architecture: pool.Architecture, Shape: pool.Shape}
		if capacity.Role == RoleWasm && pool.Size > len(pool.Members) {
			state.ProvisioningFunctions = append(state.ProvisioningFunctions, CapacityDemand{Architecture: capacity.Architecture, Slots: uint64(pool.Size - len(pool.Members))})
		}
		for _, member := range pool.Members {
			if !deref(member.LegacyIMDSDisabled) {
				pending = append(pending, fmt.Sprintf("instance %s has not positively disabled legacy IMDS endpoints", member.ID))
			}
			state.Instances = append(state.Instances, PoolInstance{ID: member.ID, Name: member.Name, State: member.State, PrivateIP: member.PrivateIP, AvailabilityDomain: member.AvailabilityDomain, FaultDomain: member.FaultDomain, Created: member.Created, Capacity: capacity, PoolID: pool.ID, ConfigurationID: pool.ConfigurationID})
		}
	}
	slices.SortFunc(state.Instances, func(a, b PoolInstance) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	state.Pending = strings.Join(pending, "; ")
	return state
}

func (o *OCIPool) configuration(ctx context.Context, id string) (*rootoci.NodeConfigurationObservation, error) {
	if id == "" {
		return nil, errors.New("observed pool configuration is unavailable")
	}
	response, err := o.management.GetInstanceConfiguration(ctx, core.GetInstanceConfigurationRequest{InstanceConfigurationId: new(id)})
	if err != nil {
		return nil, fmt.Errorf("observed configuration %s is unavailable: %w", id, err)
	}
	if deref(response.Id) != id || deref(response.CompartmentId) != o.compartmentID {
		return nil, errors.New("observed configuration differs from the signed worker compartment")
	}
	details, ok := response.InstanceDetails.(core.ComputeInstanceDetails)
	if !ok || details.LaunchDetails == nil {
		return nil, errors.New("observed configuration has no compute launch details")
	}
	launch := details.LaunchDetails
	source, ok := launch.SourceDetails.(core.InstanceConfigurationInstanceSourceViaImageDetails)
	if !ok || launch.ShapeConfig == nil {
		return nil, errors.New("observed configuration has unknown image or geometry")
	}
	return &rootoci.NodeConfigurationObservation{ID: id, Name: deref(response.DisplayName), Shape: deref(launch.Shape), ImageID: deref(source.ImageId), OCPUs: launch.ShapeConfig.Ocpus, MemoryGB: launch.ShapeConfig.MemoryInGBs, BootGB: source.BootVolumeSizeInGBs, LegacyIMDSDisabled: configurationIMDS(launch.InstanceOptions)}, nil
}

func memberIMDS(options *core.InstanceOptions) *bool {
	if options == nil {
		return nil
	}
	return options.AreLegacyImdsEndpointsDisabled
}
func configurationIMDS(options *core.InstanceConfigurationInstanceOptions) *bool {
	if options == nil {
		return nil
	}
	return options.AreLegacyImdsEndpointsDisabled
}
