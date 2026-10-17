package rootcapacity

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func (a *attempt) authorizeLaunch(ctx context.Context) error {
	if !time.Now().Before(a.receipt.LaunchExpiresAt) || !a.receipt.RetiredAt.IsZero() {
		return errors.New("original reservation no longer permits a new launch")
	}
	proof, err := a.resolver.InfrastructureSpend(a.readContext(ctx))
	if err != nil {
		return err
	}
	inventory, err := capacityinventory.New(a.factory)
	if err != nil {
		return err
	}
	quote, err := inventory.Quote(a.readContext(ctx), proof.Footprint(), a.receipt.Cell, a.receipt.CompartmentID, a.receipt.Shape,
		a.receipt.OCPUs, a.receipt.MemoryGB, a.receipt.BootGB)
	if err != nil {
		return err
	}
	snapshot, err := inventory.Read(a.readContext(ctx), proof.Footprint())
	if err != nil {
		return err
	}
	child, exists := a.record.PoolChildren[a.receipt.OperationID]
	if !exists || child.Launch == nil || child.InstanceID != "" {
		return errors.New("launch has no exact unresolved original child preparation")
	}
	management, err := a.factory.ComputeManagement()
	if err != nil {
		return err
	}
	pool, err := management.GetInstancePool(a.readContext(ctx), core.GetInstancePoolRequest{InstancePoolId: new(child.PoolID)})
	if err != nil {
		return err
	}
	if err := a.checkPool(pool.InstancePool, child.PoolID); err != nil {
		return err
	}
	if value(pool.Size) != child.TargetFrom || pool.LifecycleState != core.InstancePoolLifecycleStateRunning || value(pool.InstanceConfigurationId) != child.ConfigurationID {
		return errors.New("original launch target changed before exact provider dispatch")
	}
	members, err := a.members(ctx, management, child.PoolID)
	if err != nil {
		return err
	}
	if len(members) != child.TargetFrom {
		return errors.New("launch pool membership differs from its original target")
	}
	if err := a.knownReadyMembers(members, child.PoolID); err != nil {
		return err
	}
	compute, err := a.factory.Compute()
	if err != nil {
		return err
	}
	var page *string
	found, count := false, 0
	for pages := 0; ; pages++ {
		if pages >= 128 {
			return errors.New("compatible shape pagination exceeds its finite bound")
		}
		response, err := compute.ListShapes(a.readContext(ctx), core.ListShapesRequest{CompartmentId: new(a.receipt.CompartmentID),
			AvailabilityDomain: new(child.AvailabilityDomain), ImageId: new(a.recipe.ImageID), Page: page})
		if err != nil {
			return err
		}
		count += len(response.Items)
		if count > 2048 {
			return errors.New("actual compatible shape inventory exceeds its finite bound")
		}
		for _, shape := range response.Items {
			if value(shape.Shape) != a.recipe.Capacity.Shape {
				continue
			}
			architecture, err := catalog.ShapeArchitecture(value(shape.ProcessorDescription))
			if found || err != nil || architecture != a.recipe.Capacity.Architecture {
				return errors.Join(err, errors.New("actual launch shape is ambiguous or has another architecture"))
			}
			if err := nodescale.ValidateResources(shape, a.recipe.OCPUs, a.recipe.MemoryGB); err != nil {
				return err
			}
			found = true
		}
		if value(response.OpcNextPage) == "" {
			break
		}
		if value(page) == value(response.OpcNextPage) {
			return errors.New("compatible shape inventory repeated a page token")
		}
		page = response.OpcNextPage
	}
	if !found {
		return errors.New("exact signed image has no actual compatible launch shape in original AD")
	}
	if err := a.worker.Revalidate(a.readContext(ctx)); err != nil {
		return err
	}
	if err := budget.Revalidate(a.readContext(ctx), a.home, a.receipt, proof, quote, snapshot, time.Now()); err != nil {
		return err
	}
	if err := a.guard(ctx); err != nil {
		return err
	}
	now := time.Now()
	if !now.Before(a.receipt.LaunchExpiresAt) || !now.Before(a.worker.ExpiresAt()) || !proof.ValidAt(now) {
		return errors.New("launch authority expired during final provider authorization")
	}
	if err := snapshot.Validate(proof.Footprint(), now); err != nil {
		return err
	}
	return quote.Validate(proof.Footprint(), a.receipt.Cell, a.receipt.CompartmentID, a.receipt.Shape, a.receipt.OCPUs, a.receipt.MemoryGB, a.receipt.BootGB, now)
}

func (a *attempt) authorizeAttach(ctx context.Context) error {
	child, exists := a.record.PoolChildren[a.receipt.OperationID]
	if !exists || child.InstanceID == "" || child.BootVolumeID == "" || child.BootAttachmentID == "" || child.Launch == nil || child.Launch.AcceptedAt.IsZero() {
		return errors.New("attach has no original positive child and boot liability")
	}
	proof, err := a.resolver.InfrastructureSpend(a.readContext(ctx))
	if err != nil {
		return err
	}
	inventory, err := capacityinventory.New(a.factory)
	if err != nil {
		return err
	}
	snapshot, err := inventory.Read(a.readContext(ctx), proof.Footprint())
	if err != nil {
		return err
	}
	facts, err := a.worker.ObservePoolWorker(a.readContext(ctx), a.factory, child.InstanceID, child.ConfigurationID, child.Descriptor)
	if err != nil {
		return err
	}
	if facts.BootVolumeID != child.BootVolumeID || facts.BootAttachmentID != child.BootAttachmentID ||
		facts.Recipe.AvailabilityDomains[0] != child.AvailabilityDomain || facts.Recipe.SubnetID != child.SubnetID {
		return errors.New("attach changed the original born child's boot or placement")
	}
	management, err := a.factory.ComputeManagement()
	if err != nil {
		return err
	}
	pool, err := management.GetInstancePool(a.readContext(ctx), core.GetInstancePoolRequest{InstancePoolId: new(child.PoolID)})
	if err != nil {
		return err
	}
	if err := a.checkPool(pool.InstancePool, child.PoolID); err != nil {
		return err
	}
	members, err := a.members(ctx, management, child.PoolID)
	if err != nil {
		return err
	}
	if err := exactAttachTarget(pool.InstancePool, members, child); err != nil {
		return err
	}
	others := slices.DeleteFunc(members, func(member core.InstanceSummary) bool { return value(member.Id) == child.InstanceID })
	if err := a.knownReadyMembers(others, child.PoolID); err != nil {
		return err
	}
	if err := budget.RevalidateExisting(a.readContext(ctx), a.home, a.receipt, proof, snapshot, time.Now()); err != nil {
		return err
	}
	if err := a.guard(ctx); err != nil {
		return err
	}
	now := time.Now()
	if !now.Before(a.worker.ExpiresAt()) || !proof.ValidAt(now) {
		return errors.New("attach authority expired during final provider authorization")
	}
	return snapshot.Validate(proof.Footprint(), now)
}

// A lost attach response may be retried only for this same original child.
func exactAttachTarget(pool core.InstancePool, members []core.InstanceSummary, child region.PoolChildRecord) error {
	if pool.LifecycleState != core.InstancePoolLifecycleStateRunning || value(pool.InstanceConfigurationId) != child.ConfigurationID ||
		pool.Size == nil || len(members) != *pool.Size {
		return fmt.Errorf("%w: original attach pool is not settled", ErrPending)
	}
	target := child.TargetFrom
	for _, member := range members {
		if value(member.Id) == child.InstanceID {
			if target != child.TargetFrom || value(member.InstanceConfigurationId) != child.ConfigurationID ||
				value(member.AvailabilityDomain) != child.AvailabilityDomain || value(member.CompartmentId) != value(pool.CompartmentId) || value(member.State) != "RUNNING" {
				return errors.New("attach replay member differs from original child")
			}
			target++
		}
	}
	if *pool.Size != target || target >= nodescale.MaxPoolNodes && target == child.TargetFrom {
		return errors.New("attach pool changed its original exact target")
	}
	return nil
}

func (a *attempt) readReadyChild(ctx context.Context, management core.ComputeManagementClient, child region.PoolChildRecord) (region.PoolWorkerObservation, error) {
	member, err := management.GetInstancePoolInstance(a.readContext(ctx), core.GetInstancePoolInstanceRequest{InstancePoolId: new(child.PoolID), InstanceId: new(child.InstanceID)})
	if err != nil {
		return region.PoolWorkerObservation{}, err
	}
	if value(member.Id) != child.InstanceID || value(member.InstancePoolId) != child.PoolID || value(member.InstanceConfigurationId) != child.ConfigurationID ||
		value(member.CompartmentId) != a.record.CapacityPools[child.PoolID].CompartmentID || value(member.AvailabilityDomain) != child.AvailabilityDomain ||
		member.LifecycleState != core.InstancePoolInstanceLifecycleStateActive {
		return region.PoolWorkerObservation{}, fmt.Errorf("%w: original child is not an exact active member", ErrPending)
	}
	facts, err := a.worker.ObservePoolWorker(a.readContext(ctx), a.factory, child.InstanceID, child.ConfigurationID, child.Descriptor)
	if err != nil {
		return region.PoolWorkerObservation{}, err
	}
	if facts.BootVolumeID != child.BootVolumeID || facts.BootAttachmentID != child.BootAttachmentID ||
		facts.Recipe.AvailabilityDomains[0] != child.AvailabilityDomain || facts.Recipe.SubnetID != child.SubnetID {
		return region.PoolWorkerObservation{}, errors.New("active pool child changed original boot or placement")
	}
	pool, err := management.GetInstancePool(a.readContext(ctx), core.GetInstancePoolRequest{InstancePoolId: new(child.PoolID)})
	if err != nil {
		return region.PoolWorkerObservation{}, err
	}
	if err := a.checkPool(pool.InstancePool, child.PoolID); err != nil {
		return region.PoolWorkerObservation{}, err
	}
	if pool.LifecycleState != core.InstancePoolLifecycleStateRunning {
		return region.PoolWorkerObservation{}, fmt.Errorf("%w: exact original attach target is not settled", ErrPending)
	}
	return facts, a.guard(ctx)
}
