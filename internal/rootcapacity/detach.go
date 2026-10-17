package rootcapacity

import (
	"context"
	"errors"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// Original provenance and actual pool facts apply equally to known retirement
// and membership-only quarantine; neither tags nor discovery supply ownership.
func (a *attempt) originalPool(ctx context.Context, management core.ComputeManagementClient, poolID string) (core.InstancePool, error) {
	protected, exists := a.record.CapacityPools[poolID]
	create, created := a.record.CapacityCreates[protected.OperationID+":pool"]
	if !exists || !created || create.ResourceID != poolID || create.Request.AcceptedAt.IsZero() ||
		create.Request.RequestSHA256 != protected.Create.RequestSHA256 || protected.Create.AcceptedAt.IsZero() {
		return core.InstancePool{}, errors.New("pool lacks its exact original protected positive create")
	}
	response, err := management.GetInstancePool(a.readContext(ctx), core.GetInstancePoolRequest{InstancePoolId: new(poolID)})
	if err != nil {
		return core.InstancePool{}, err
	}
	pool := response.InstancePool
	if value(pool.Id) != poolID || value(pool.CompartmentId) != protected.CompartmentID || value(pool.DisplayName) != protected.PoolName ||
		pool.Size == nil || *pool.Size < 0 || *pool.Size > nodescale.MaxPoolNodes || len(pool.LoadBalancers) != 0 ||
		value(pool.InstanceConfigurationId) != protected.CurrentConfigurationID {
		return core.InstancePool{}, errors.New("actual pool changed its protected identity or current configuration")
	}
	config, configured := protected.Configurations[value(pool.InstanceConfigurationId)]
	if !configured || config.Create.AcceptedAt.IsZero() {
		return core.InstancePool{}, errors.New("actual pool uses an unproven original configuration")
	}
	placements := make([]core.CreateInstancePoolPlacementConfigurationDetails, 0, len(pool.PlacementConfigurations))
	for _, placement := range pool.PlacementConfigurations {
		if value(placement.ComputeClusterId) != "" || len(placement.FaultDomains) != 0 || len(placement.SecondaryVnicSubnets) != 0 {
			return core.InstancePool{}, errors.New("actual pool changed original finite placement geometry")
		}
		subnet := value(placement.PrimarySubnetId)
		if placement.PrimaryVnicSubnets != nil {
			primary := placement.PrimaryVnicSubnets
			if value(primary.IsAssignIpv6Ip) || len(primary.Ipv6AddressIpv6SubnetCidrPairDetails) != 0 ||
				subnet != "" && subnet != value(primary.SubnetId) {
				return core.InstancePool{}, errors.New("actual pool changed original primary network placement")
			}
			subnet = value(primary.SubnetId)
		}
		placements = append(placements, core.CreateInstancePoolPlacementConfigurationDetails{AvailabilityDomain: placement.AvailabilityDomain,
			PrimaryVnicSubnets: &core.InstancePoolPlacementPrimarySubnet{SubnetId: new(subnet)}})
	}
	placementSHA, err := oci.PoolPlacementSHA256(placements)
	if err != nil || placementSHA != create.PlacementSHA256 {
		return core.InstancePool{}, errors.Join(err, errors.New("actual pool placement differs from its exact original protected create"))
	}
	return pool, a.guard(ctx)
}

// An unknown response permits replay of the exact retained decrement, never a
// new token or an inference that disappearance completed the original action.
func exactDetachTarget(pool core.InstancePool, members []core.InstanceSummary, instanceID string, targetFrom int, unknown bool) error {
	if targetFrom < 1 || targetFrom > nodescale.MaxPoolNodes || pool.Size == nil || len(members) != *pool.Size ||
		pool.LifecycleState != core.InstancePoolLifecycleStateRunning {
		return fmt.Errorf("%w: original detach target is not settled", ErrPending)
	}
	found := false
	for _, member := range members {
		if value(member.Id) != instanceID {
			continue
		}
		if found || value(member.CompartmentId) != value(pool.CompartmentId) {
			return errors.New("detach target has conflicting exact membership")
		}
		found = true
	}
	if found && *pool.Size == targetFrom || !found && unknown && *pool.Size == targetFrom-1 {
		return nil
	}
	return errors.New("detach target changed its original member or exact decrement")
}

func (a *attempt) detachCompleted(ctx context.Context, management core.ComputeManagementClient, poolID, instanceID string, targetFrom int, wire *region.PoolWireRecord) (bool, error) {
	complete, err := a.workCompleted(ctx, wire, poolID)
	if err != nil || !complete {
		return false, err
	}
	if err := a.save(ctx); err != nil {
		return false, err
	}
	pool, err := a.originalPool(ctx, management, poolID)
	if err != nil {
		return false, err
	}
	members, err := a.members(ctx, management, poolID)
	if err != nil {
		return false, err
	}
	if pool.LifecycleState != core.InstancePoolLifecycleStateRunning || value(pool.Size) != targetFrom-1 || len(members) != targetFrom-1 {
		return false, nil
	}
	for _, member := range members {
		if value(member.Id) == instanceID {
			return false, nil
		}
	}
	return true, a.guard(ctx)
}
