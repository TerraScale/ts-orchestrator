package rootcapacity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func (a *attempt) reserveOriginal(ctx context.Context) error {
	receipt, err := a.receipt.FinancialReceipt()
	if err != nil {
		return err
	}
	if a.record.CapacityLedger == nil {
		a.record.CapacityLedger = &capacityledger.Ledger{}
	}
	if err := a.record.CapacityLedger.Reserve(receipt); err != nil {
		return err
	}
	if a.record.CapacityCreates == nil {
		a.record.CapacityCreates = map[string]region.PoolCreateRecord{}
	}
	if a.record.CapacityPools == nil {
		a.record.CapacityPools = map[string]region.PoolResourceRecord{}
	}
	if a.record.PoolChildren == nil {
		a.record.PoolChildren = map[string]region.PoolChildRecord{}
	}
	return a.save(ctx)
}

func (a *attempt) ensurePool(ctx context.Context, management core.ComputeManagementClient) (string, string, error) {
	if child, exists := a.record.PoolChildren[a.receipt.OperationID]; exists {
		pool, known := a.record.CapacityPools[child.PoolID]
		config, configured := pool.Configurations[child.ConfigurationID]
		if !known || !configured || config.RecipeSHA256 != child.RecipeSHA256 || child.RecipeSHA256 != a.recipe.SHA256() {
			return "", "", errors.New("original child lost its exact pool configuration provenance")
		}
		if err := a.claimPool(ctx, child.PoolID); err != nil {
			return "", "", err
		}
		if err := a.verifyConfiguration(ctx, management, child.ConfigurationID, config.ConfigurationSHA256); err != nil {
			return "", "", err
		}
		actual, err := a.originalPool(ctx, management, child.PoolID)
		if err != nil {
			return "", "", err
		}
		if value(actual.InstanceConfigurationId) != child.ConfigurationID {
			return "", "", errors.New("unresolved original child cannot move to a successor pool configuration")
		}
		return child.PoolID, child.ConfigurationID, nil
	}
	name := nodescale.PoolName(a.recipe.Cell, a.recipe.Capacity)
	poolID := ""
	for id, pool := range a.record.CapacityPools {
		if pool.PoolName != name {
			continue
		}
		if poolID != "" || pool.CompartmentID != a.receipt.CompartmentID {
			return "", "", errors.New("logical capacity pool has conflicting protected original identities")
		}
		poolID = id
	}
	for _, create := range a.record.CapacityCreates {
		if create.PoolName == name && create.ResourceID == "" && create.OperationID != a.receipt.OperationID {
			return "", "", fmt.Errorf("%w: original pool inception must recover under its retained operation", ErrPending)
		}
	}
	if poolID == "" {
		if _, prepared := a.record.CapacityCreates[a.receipt.OperationID+":pool"]; !prepared {
			if err := a.rejectPoolCollision(ctx, management, name); err != nil {
				return "", "", err
			}
		}
	}
	if poolID != "" {
		if err := a.claimPool(ctx, poolID); err != nil {
			return "", "", err
		}
	}
	configurationID, err := a.ensureConfiguration(ctx, management, poolID)
	if err != nil {
		return "", "", err
	}
	if poolID == "" {
		poolID, err = a.createPool(ctx, management, configurationID)
		if err != nil {
			return "", "", err
		}
		if err := a.claimPool(ctx, poolID); err != nil {
			return "", "", err
		}
	}
	response, err := management.GetInstancePool(a.readContext(ctx), core.GetInstancePoolRequest{InstancePoolId: new(poolID)})
	if err != nil {
		return "", "", err
	}
	if err := a.checkPool(response.InstancePool, poolID); err != nil {
		return "", "", err
	}
	if response.LifecycleState != core.InstancePoolLifecycleStateRunning {
		return "", "", fmt.Errorf("%w: original pool is still provisioning", ErrPending)
	}
	_, pendingPoint := a.record.CapacityPools[poolID].ConfigurationUpdates[a.operation]
	if value(response.InstanceConfigurationId) != configurationID || pendingPoint {
		if err := a.pointConfiguration(ctx, management, response, configurationID); err != nil {
			return "", "", err
		}
	}
	return poolID, configurationID, nil
}

func (a *attempt) ensureConfiguration(ctx context.Context, management core.ComputeManagementClient, poolID string) (string, error) {
	profileSHA, err := digestValue(a.worker.Profile().Profile())
	if err != nil {
		return "", err
	}
	if poolID != "" {
		found := ""
		for id, config := range a.record.CapacityPools[poolID].Configurations {
			if config.RecipeSHA256 == a.recipe.SHA256() && config.ProfileSHA256 == profileSHA {
				if found != "" {
					return "", errors.New("one pool recipe has conflicting protected configurations")
				}
				found = id
			}
		}
		if found != "" {
			return found, a.verifyConfiguration(ctx, management, found, a.record.CapacityPools[poolID].Configurations[found].ConfigurationSHA256)
		}
	}
	request := a.configurationRequest()
	details := request.CreateInstanceConfiguration.(core.CreateInstanceConfigurationDetails)
	configurationSHA, err := oci.PoolConfigurationSHA256(details.InstanceDetails)
	if err != nil {
		return "", err
	}
	key := a.receipt.OperationID + ":configuration"
	create, exists := a.record.CapacityCreates[key]
	if !exists {
		wire, err := prepareWire(request, http.MethodPost, configurationCreatePath)
		if err != nil {
			return "", err
		}
		create = region.PoolCreateRecord{OperationID: a.receipt.OperationID, PoolName: nodescale.PoolName(a.recipe.Cell, a.recipe.Capacity), Kind: "configuration",
			RecipeSHA256: a.recipe.SHA256(), ProfileSHA256: profileSHA, GrantSHA256: a.receipt.GrantSHA256, Generation: a.receipt.GrantGeneration, ConfigurationSHA256: configurationSHA, Request: *wire}
		a.record.CapacityCreates[key] = create
		if err := a.save(ctx); err != nil {
			return "", err
		}
	}
	if create.ConfigurationSHA256 != configurationSHA || create.RecipeSHA256 != a.recipe.SHA256() {
		return "", errors.New("configuration retry differs from its original protected body")
	}
	if create.ResourceID == "" {
		response, err := management.CreateInstanceConfiguration(a.writeContext(ctx, "configuration"), request)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(value(response.Id), "ocid1.instanceconfiguration.") {
			return "", errors.New("configuration create has no positive original SDK identity")
		}
		create = a.record.CapacityCreates[key]
		create.ResourceID = value(response.Id)
		acceptedWire(&create.Request, response.OpcRequestId, nil)
		a.record.CapacityCreates[key] = create
		if err := a.save(ctx); err != nil {
			return "", err
		}
	}
	if err := a.verifyConfiguration(ctx, management, create.ResourceID, configurationSHA); err != nil {
		return "", err
	}
	if poolID != "" {
		pool := a.record.CapacityPools[poolID]
		pool.Configurations[create.ResourceID] = configurationRecord(create)
		a.record.CapacityPools[poolID] = pool
		if err := a.save(ctx); err != nil {
			return "", err
		}
	}
	return create.ResourceID, nil
}

func configurationRecord(create region.PoolCreateRecord) region.PoolConfigurationRecord {
	return region.PoolConfigurationRecord{ConfigurationID: create.ResourceID, OperationID: create.OperationID, RecipeSHA256: create.RecipeSHA256,
		ConfigurationSHA256: create.ConfigurationSHA256, ProfileSHA256: create.ProfileSHA256, GrantSHA256: create.GrantSHA256, Generation: create.Generation, Create: create.Request}
}

func (a *attempt) verifyConfiguration(ctx context.Context, management core.ComputeManagementClient, id, expectedSHA string) error {
	response, err := management.GetInstanceConfiguration(a.readContext(ctx), core.GetInstanceConfigurationRequest{InstanceConfigurationId: new(id)})
	if err != nil {
		return err
	}
	actualSHA, err := oci.PoolConfigurationSHA256(response.InstanceDetails)
	if err != nil || value(response.Id) != id || value(response.CompartmentId) != a.receipt.CompartmentID || actualSHA != expectedSHA {
		return errors.Join(err, errors.New("original configuration readback differs from protected original SDK body"))
	}
	return nil
}

func (a *attempt) createPool(ctx context.Context, management core.ComputeManagementClient, configurationID string) (string, error) {
	request := a.poolRequest(configurationID)
	placementSHA, err := oci.PoolPlacementSHA256(request.PlacementConfigurations)
	if err != nil {
		return "", err
	}
	key := a.receipt.OperationID + ":pool"
	create, exists := a.record.CapacityCreates[key]
	configuration := a.record.CapacityCreates[a.receipt.OperationID+":configuration"]
	if !exists {
		wire, err := prepareWire(request, http.MethodPost, poolCreatePath)
		if err != nil {
			return "", err
		}
		create = region.PoolCreateRecord{OperationID: a.receipt.OperationID, PoolName: value(request.DisplayName), Kind: "pool", RecipeSHA256: a.recipe.SHA256(),
			GrantSHA256: a.receipt.GrantSHA256, Generation: a.receipt.GrantGeneration, ConfigurationID: configurationID, ProfileSHA256: configuration.ProfileSHA256,
			ConfigurationSHA256: configuration.ConfigurationSHA256, PlacementSHA256: placementSHA, Request: *wire}
		a.record.CapacityCreates[key] = create
		if err := a.save(ctx); err != nil {
			return "", err
		}
	}
	if create.ConfigurationID != configurationID || create.PlacementSHA256 != placementSHA || create.RecipeSHA256 != a.recipe.SHA256() {
		return "", errors.New("pool retry differs from original configuration or placement")
	}
	if create.ResourceID == "" {
		response, err := management.CreateInstancePool(a.writeContext(ctx, "pool"), request)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(value(response.Id), "ocid1.instancepool.") {
			return "", errors.New("pool create has no positive original SDK identity")
		}
		create = a.record.CapacityCreates[key]
		create.ResourceID = value(response.Id)
		acceptedWire(&create.Request, response.OpcRequestId, nil)
		a.record.CapacityCreates[key] = create
		if err := a.save(ctx); err != nil {
			return "", err
		}
	}
	if _, exists := a.record.CapacityPools[create.ResourceID]; !exists {
		a.record.CapacityPools[create.ResourceID] = region.PoolResourceRecord{PoolID: create.ResourceID, PoolName: create.PoolName, CompartmentID: a.receipt.CompartmentID,
			OperationID: create.OperationID, GrantSHA256: create.GrantSHA256, Generation: create.Generation, Epoch: a.original.Epoch,
			Role: a.recipe.Capacity.Role, Architecture: a.recipe.Capacity.Architecture, Shape: a.recipe.Capacity.Shape, ProfileSHA256: create.ProfileSHA256, RecipeSHA256: create.RecipeSHA256,
			Create: create.Request, CurrentConfigurationID: configurationID, Configurations: map[string]region.PoolConfigurationRecord{configurationID: configurationRecord(configuration)},
			ActiveOperationID: a.operation}
		if err := a.save(ctx); err != nil {
			return "", err
		}
	}
	return create.ResourceID, nil
}

func (a *attempt) checkPool(pool core.InstancePool, id string) error {
	if value(pool.Id) != id || value(pool.CompartmentId) != a.record.CapacityPools[id].CompartmentID || value(pool.DisplayName) != a.record.CapacityPools[id].PoolName ||
		pool.Size == nil || *pool.Size < 0 || *pool.Size > nodescale.MaxPoolNodes || len(pool.LoadBalancers) != 0 || len(pool.PlacementConfigurations) != len(a.recipe.AvailabilityDomains) {
		return errors.New("protected pool actual identity, size or placement changed")
	}
	for i, placement := range pool.PlacementConfigurations {
		subnet := value(placement.PrimarySubnetId)
		if placement.PrimaryVnicSubnets != nil {
			subnet = value(placement.PrimaryVnicSubnets.SubnetId)
		}
		if value(placement.AvailabilityDomain) != a.recipe.AvailabilityDomains[i] || subnet != a.recipe.SubnetID {
			return errors.New("pool placement differs from independently signed recipe")
		}
	}
	return nil
}

func (a *attempt) pointConfiguration(ctx context.Context, management core.ComputeManagementClient, observed core.GetInstancePoolResponse, configurationID string) error {
	pool := a.record.CapacityPools[a.poolID]
	if pool.ConfigurationUpdates == nil {
		pool.ConfigurationUpdates = map[string]region.PoolConfigurationUpdateRecord{}
	}
	point, exists := pool.ConfigurationUpdates[a.operation]
	if !exists {
		if value(observed.Etag) == "" {
			return errors.New("pool configuration point has no current conditional ETag")
		}
		request := core.UpdateInstancePoolRequest{InstancePoolId: new(a.poolID), IfMatch: observed.Etag,
			UpdateInstancePoolDetails: core.UpdateInstancePoolDetails{InstanceConfigurationId: new(configurationID)}, RequestMetadata: noRetry()}
		wire, err := prepareWire(request, http.MethodPut, "/instancePools/{instancePoolId}")
		if err != nil {
			return err
		}
		point = region.PoolConfigurationUpdateRecord{ConfigurationID: configurationID, Request: *wire}
		pool.ConfigurationUpdates[a.operation] = point
		a.record.CapacityPools[a.poolID] = pool
		if err := a.save(ctx); err != nil {
			return err
		}
	}
	if point.ConfigurationID != configurationID {
		return errors.New("pool operation already selected another exact configuration")
	}
	if point.Request.AcceptedAt.IsZero() {
		request := core.UpdateInstancePoolRequest{InstancePoolId: new(a.poolID), IfMatch: new(point.Request.IfMatch),
			UpdateInstancePoolDetails: core.UpdateInstancePoolDetails{InstanceConfigurationId: new(configurationID)}, RequestMetadata: noRetry()}
		response, err := management.UpdateInstancePool(a.writeContext(ctx, "point"), request)
		if err != nil {
			return err
		}
		if value(response.Id) != a.poolID || value(response.CompartmentId) != a.receipt.CompartmentID || value(response.InstanceConfigurationId) != configurationID {
			return errors.New("configuration point response differs from exact original pool and configuration")
		}
		pool = a.record.CapacityPools[a.poolID]
		point = pool.ConfigurationUpdates[a.operation]
		acceptedWire(&point.Request, response.OpcRequestId, nil)
		pool.ConfigurationUpdates[a.operation] = point
		a.record.CapacityPools[a.poolID] = pool
		if err := a.save(ctx); err != nil {
			return err
		}
	}
	fresh, err := management.GetInstancePool(a.readContext(ctx), core.GetInstancePoolRequest{InstancePoolId: new(a.poolID)})
	if err != nil {
		return err
	}
	if err := a.checkPool(fresh.InstancePool, a.poolID); err != nil {
		return err
	}
	if value(fresh.InstanceConfigurationId) != configurationID || fresh.LifecycleState != core.InstancePoolLifecycleStateRunning {
		return fmt.Errorf("%w: original configuration point has not reached exact running readback", ErrPending)
	}
	pool.CurrentConfigurationID = configurationID
	a.record.CapacityPools[a.poolID] = pool
	return a.save(ctx)
}

// A same-name provider object blocks inception; discovery never supplies origin.
func (a *attempt) rejectPoolCollision(ctx context.Context, management core.ComputeManagementClient, name string) error {
	var page *string
	for pages := 0; pages < 128; pages++ {
		response, err := management.ListInstancePools(a.readContext(ctx), core.ListInstancePoolsRequest{
			CompartmentId: new(a.receipt.CompartmentID), DisplayName: new(name), Page: page})
		if err != nil {
			return err
		}
		if len(response.Items) > 1024 {
			return errors.New("pool collision inventory exceeds its finite bound")
		}
		for _, pool := range response.Items {
			if value(pool.DisplayName) != name || value(pool.CompartmentId) != a.receipt.CompartmentID {
				return errors.New("pool collision inventory returned another logical scope")
			}
			if pool.LifecycleState != core.InstancePoolSummaryLifecycleStateTerminated {
				return errors.New("logical pool name already exists without original protected inception")
			}
		}
		if value(response.OpcNextPage) == "" {
			return nil
		}
		if value(response.OpcNextPage) == value(page) {
			return errors.New("pool collision inventory repeated a page token")
		}
		page = response.OpcNextPage
	}
	return errors.New("pool collision pagination exceeds its finite bound")
}
