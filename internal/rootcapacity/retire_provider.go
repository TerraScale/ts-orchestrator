package rootcapacity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func terminateRequest(child region.PoolChildRecord, etag string) core.TerminateInstanceRequest {
	return core.TerminateInstanceRequest{InstanceId: new(child.InstanceID), IfMatch: new(etag), PreserveBootVolume: new(true),
		PreserveDataVolumesCreatedAtLaunch: new(true), RequestMetadata: noRetry()}
}

func deleteBootRequest(child region.PoolChildRecord, etag string) core.DeleteBootVolumeRequest {
	return core.DeleteBootVolumeRequest{BootVolumeId: new(child.BootVolumeID), IfMatch: new(etag), RequestMetadata: noRetry()}
}

func (a *attempt) originalInstance(ctx context.Context, child region.PoolChildRecord) (core.GetInstanceResponse, error) {
	compute, err := a.factory.Compute()
	if err != nil {
		return core.GetInstanceResponse{}, err
	}
	instance, err := compute.GetInstance(a.readContext(ctx), core.GetInstanceRequest{InstanceId: new(child.InstanceID)})
	if err != nil {
		return core.GetInstanceResponse{}, err
	}
	binding := a.lifecycle.Binding()
	if value(instance.Id) != child.InstanceID || value(instance.InstanceConfigurationId) != child.ConfigurationID ||
		value(instance.CompartmentId) != binding.CompartmentID || value(instance.AvailabilityDomain) != child.AvailabilityDomain ||
		value(instance.Shape) != binding.Shape || instance.ShapeConfig == nil || value(instance.ShapeConfig.Ocpus) != 2 || value(instance.ShapeConfig.MemoryInGBs) != 12 ||
		instance.Metadata[hostboot.MetadataKey] != child.Descriptor || value(instance.Etag) == "" {
		return core.GetInstanceResponse{}, errors.New("cleanup instance differs from exact original protected birth, descriptor or geometry")
	}
	return instance, a.guard(ctx)
}

func (a *attempt) originalBoot(ctx context.Context, child region.PoolChildRecord) (core.GetBootVolumeResponse, error) {
	storage, err := a.factory.Blockstorage()
	if err != nil {
		return core.GetBootVolumeResponse{}, err
	}
	boot, err := storage.GetBootVolume(a.readContext(ctx), core.GetBootVolumeRequest{BootVolumeId: new(child.BootVolumeID)})
	if err != nil {
		return core.GetBootVolumeResponse{}, err
	}
	if value(boot.Id) != child.BootVolumeID || value(boot.CompartmentId) != a.lifecycle.Binding().CompartmentID ||
		value(boot.AvailabilityDomain) != child.AvailabilityDomain || value(boot.SizeInGBs) != 50 || value(boot.Etag) == "" {
		return core.GetBootVolumeResponse{}, errors.New("cleanup boot differs from original positive boot identity, scope or geometry")
	}
	return boot, a.guard(ctx)
}

// The original configuration is read independently of today's image channel.
func (a *attempt) originalConfiguration(ctx context.Context, child region.PoolChildRecord) error {
	management, err := a.factory.ComputeManagement()
	if err != nil {
		return err
	}
	actual, err := management.GetInstanceConfiguration(a.readContext(ctx), core.GetInstanceConfigurationRequest{InstanceConfigurationId: new(child.ConfigurationID)})
	if err != nil {
		return err
	}
	configuration := a.record.CapacityPools[child.PoolID].Configurations[child.ConfigurationID]
	actualSHA, err := oci.PoolConfigurationSHA256(actual.InstanceDetails)
	if err != nil || value(actual.Id) != child.ConfigurationID || value(actual.CompartmentId) != a.lifecycle.Binding().CompartmentID ||
		actualSHA != configuration.ConfigurationSHA256 {
		return errors.Join(err, errors.New("cleanup original configuration lost exact accepted SDK provenance"))
	}
	return a.guard(ctx)
}

func (a *attempt) terminateOriginal(ctx context.Context, child region.PoolChildRecord) (bool, error) {
	if child.InstanceTerminal != nil {
		return true, a.guard(ctx)
	}
	instance, err := a.originalInstance(ctx, child)
	if err != nil {
		return false, err
	}
	if instance.LifecycleState == core.InstanceLifecycleStateTerminated {
		return a.retainTerminal(ctx, child, "instance", value(instance.Etag), value(instance.OpcRequestId), instance.Instance)
	}
	if child.Terminate == nil {
		if err := a.verifyRetirementDrain(ctx, child, true, true); err != nil {
			return false, err
		}
		if instance.LifecycleState != core.InstanceLifecycleStateRunning && instance.LifecycleState != core.InstanceLifecycleStateStopped {
			return false, errors.New("unprepared original termination target is not a live exact worker")
		}
		child.Terminate, err = prepareWire(terminateRequest(child, value(instance.Etag)), http.MethodDelete, "/instances/{instanceId}")
		if err != nil {
			return false, err
		}
		child.Terminate.ExpiresAt = a.retirementDeadline()
		child.Stage = region.PoolChildTerminating
		a.record.PoolChildren[child.OperationID] = child
		if err := a.save(ctx); err != nil {
			return false, err
		}
	}
	if child.Terminate.AcceptedAt.IsZero() {
		if err := retirementWireLive(child.Terminate); err != nil {
			return false, err
		}
		compute, err := a.factory.Compute()
		if err != nil {
			return false, err
		}
		response, err := compute.TerminateInstance(a.writeContext(ctx, "terminate"), terminateRequest(child, child.Terminate.IfMatch))
		if err != nil {
			return false, err
		}
		child = a.record.PoolChildren[child.OperationID]
		acceptedWire(child.Terminate, response.OpcRequestId, response.OpcWorkRequestId)
		a.record.PoolChildren[child.OperationID] = child
		if err := a.save(ctx); err != nil {
			return false, err
		}
	}
	instance, err = a.originalInstance(ctx, child)
	if err != nil || instance.LifecycleState != core.InstanceLifecycleStateTerminated {
		return false, err
	}
	return a.retainTerminal(ctx, child, "instance", value(instance.Etag), value(instance.OpcRequestId), instance.Instance)
}

func (a *attempt) deleteOriginalBoot(ctx context.Context, child region.PoolChildRecord) (bool, error) {
	if child.BootTerminal != nil {
		return true, a.guard(ctx)
	}
	boot, err := a.originalBoot(ctx, child)
	if err != nil {
		return false, err
	}
	if boot.LifecycleState == core.BootVolumeLifecycleStateTerminated {
		return a.retainTerminal(ctx, child, "boot", value(boot.Etag), value(boot.OpcRequestId), boot.BootVolume)
	}
	if child.DeleteBoot == nil {
		if err := a.verifyRetirementDrain(ctx, child, true, true); err != nil {
			return false, err
		}
		if boot.LifecycleState != core.BootVolumeLifecycleStateAvailable {
			return false, fmt.Errorf("%w: preserved original boot is not available for exact deletion", ErrPending)
		}
		child.DeleteBoot, err = prepareWire(deleteBootRequest(child, value(boot.Etag)), http.MethodDelete, "/bootVolumes/{bootVolumeId}")
		if err != nil {
			return false, err
		}
		child.DeleteBoot.ExpiresAt = a.retirementDeadline()
		a.record.PoolChildren[child.OperationID] = child
		if err := a.save(ctx); err != nil {
			return false, err
		}
	}
	if child.DeleteBoot.AcceptedAt.IsZero() {
		if err := retirementWireLive(child.DeleteBoot); err != nil {
			return false, err
		}
		storage, err := a.factory.Blockstorage()
		if err != nil {
			return false, err
		}
		response, err := storage.DeleteBootVolume(a.writeContext(ctx, "delete-boot"), deleteBootRequest(child, child.DeleteBoot.IfMatch))
		if err != nil {
			return false, err
		}
		child = a.record.PoolChildren[child.OperationID]
		acceptedWire(child.DeleteBoot, response.OpcRequestId, nil)
		a.record.PoolChildren[child.OperationID] = child
		if err := a.save(ctx); err != nil {
			return false, err
		}
	}
	boot, err = a.originalBoot(ctx, child)
	if err != nil || boot.LifecycleState != core.BootVolumeLifecycleStateTerminated {
		return false, err
	}
	return a.retainTerminal(ctx, child, "boot", value(boot.Etag), value(boot.OpcRequestId), boot.BootVolume)
}

func (a *attempt) retainTerminal(ctx context.Context, child region.PoolChildRecord, kind, etag, requestID string, response any) (bool, error) {
	if err := a.verifyRetirementDrain(ctx, child, true, false); err != nil {
		return false, err
	}
	wire, resourceID := child.Terminate, child.InstanceID
	if kind == "boot" {
		if child.InstanceTerminal == nil {
			return false, errors.New("boot terminal observation lacks original positive instance terminal history")
		}
		wire, resourceID = child.DeleteBoot, child.BootVolumeID
	}
	observed, err := terminalObservation(wire, resourceID, etag, requestID, response, time.Now().UTC())
	if err != nil {
		return false, err
	}
	if kind == "boot" {
		child.BootTerminal = observed
	} else {
		child.InstanceTerminal = observed
	}
	a.record.PoolChildren[child.OperationID] = child
	return true, a.save(ctx)
}

func terminalObservation(wire *region.PoolWireRecord, resourceID, etag, requestID string, response any, now time.Time) (*region.PoolTerminalObservation, error) {
	if wire == nil || wire.Attempts == 0 || wire.IfMatch == "" || wire.ExpiresAt.IsZero() ||
		wire.AcceptedAt.IsZero() && !wire.EverUnknown && wire.PendingAttemptID == "" ||
		!wire.LastAttemptAt.Before(wire.ExpiresAt) || now.Before(wire.LastAttemptAt) || etag == "" {
		return nil, errors.New("positive terminal response has no original conditional dispatched deletion")
	}
	switch actual := response.(type) {
	case core.Instance:
		if value(actual.Id) != resourceID || actual.LifecycleState != core.InstanceLifecycleStateTerminated {
			return nil, errors.New("instance SDK response is not the exact positive terminal target")
		}
	case core.BootVolume:
		if value(actual.Id) != resourceID || actual.LifecycleState != core.BootVolumeLifecycleStateTerminated {
			return nil, errors.New("boot SDK response is not the exact positive terminal target")
		}
	default:
		return nil, errors.New("terminal observation requires the actual typed SDK instance or boot response")
	}
	responseSHA, err := digestValue(response)
	if err != nil {
		return nil, err
	}
	return &region.PoolTerminalObservation{ResourceID: resourceID, Request: *wire, LifecycleState: "TERMINATED", ResponseSHA256: responseSHA,
		ETag: etag, OpcRequestID: requestID, TerminalObservedAt: now}, nil
}

func (a *attempt) authorizeRetirement(ctx context.Context, kind string) error {
	child, exists := a.record.PoolChildren[a.birthOperation]
	if !exists || child.Stage == region.PoolChildRetired || child.RemovalOperationID != a.operation {
		return errors.New("retirement has no consumed exact original child and drain")
	}
	if err := a.verifyRetirementDrain(ctx, child, true, true); err != nil {
		return err
	}
	wire := a.wire(kind)
	if wire == nil || wire.ExpiresAt.IsZero() || !time.Now().Before(wire.ExpiresAt) ||
		kind == "terminate" && child.InstanceTerminal != nil || kind == "delete-boot" && child.BootTerminal != nil {
		return errors.New("original destructive dispatch is expired or already positively terminal")
	}
	if err := a.originalConfiguration(ctx, child); err != nil {
		return err
	}
	management, err := a.factory.ComputeManagement()
	if err != nil {
		return err
	}
	pool, err := a.originalPool(ctx, management, child.PoolID)
	if err != nil {
		return err
	}
	members, err := a.members(ctx, management, child.PoolID)
	if err != nil {
		return err
	}
	if kind == "detach" {
		if child.Detach == nil {
			return errors.New("known detach lacks its original prepared wire")
		}
		for _, member := range members {
			if value(member.Id) == child.InstanceID && (value(member.InstanceConfigurationId) != child.ConfigurationID || value(member.AvailabilityDomain) != child.AvailabilityDomain) {
				return errors.New("known detach member changed original configuration or placement")
			}
		}
		if err := exactDetachTarget(pool, members, child.InstanceID, child.DetachTargetFrom, child.Detach.EverUnknown); err != nil {
			return err
		}
	} else {
		if child.Detach == nil || child.Detach.AcceptedAt.IsZero() || child.Detach.WorkCompletedAt.IsZero() || child.DetachedAt.IsZero() ||
			pool.LifecycleState != core.InstancePoolLifecycleStateRunning || value(pool.Size) != child.DetachTargetFrom-1 || len(members) != child.DetachTargetFrom-1 {
			return errors.New("termination or boot deletion lacks completed exact nonterminating pool removal")
		}
		for _, member := range members {
			if value(member.Id) == child.InstanceID {
				return errors.New("original child rejoined pool before terminal cleanup")
			}
		}
	}
	var instance core.GetInstanceResponse
	if kind != "delete-boot" {
		instance, err = a.originalInstance(ctx, child)
		if err != nil {
			return err
		}
	}
	boot, err := a.originalBoot(ctx, child)
	if err != nil {
		return err
	}
	compute, err := a.factory.Compute()
	if err != nil {
		return err
	}
	attachments, err := compute.ListBootVolumeAttachments(a.readContext(ctx), core.ListBootVolumeAttachmentsRequest{
		CompartmentId: new(a.lifecycle.Binding().CompartmentID), AvailabilityDomain: new(child.AvailabilityDomain), BootVolumeId: new(child.BootVolumeID)})
	if err != nil {
		return err
	}
	if value(attachments.OpcNextPage) != "" {
		return errors.New("original boot attachment inventory exceeds finite exact scope")
	}
	attached := false
	for _, attachment := range attachments.Items {
		if value(attachment.BootVolumeId) != child.BootVolumeID || value(attachment.CompartmentId) != a.lifecycle.Binding().CompartmentID ||
			value(attachment.AvailabilityDomain) != child.AvailabilityDomain {
			return errors.New("original boot attachment inventory returned conflicting scope")
		}
		if attachment.LifecycleState == core.BootVolumeAttachmentLifecycleStateDetached {
			continue
		}
		if attached || value(attachment.Id) != child.BootAttachmentID || value(attachment.InstanceId) != child.InstanceID ||
			attachment.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached {
			return errors.New("original boot has another or unsettled attachment")
		}
		attached = true
	}
	if kind == "delete-boot" {
		if attached || child.InstanceTerminal == nil ||
			child.DeleteBoot == nil || value(boot.Etag) != child.DeleteBoot.IfMatch || boot.LifecycleState != core.BootVolumeLifecycleStateAvailable {
			return errors.New("boot deletion lacks positive original instance termination and exact idle preserved boot")
		}
	} else {
		if !attached || boot.LifecycleState != core.BootVolumeLifecycleStateAvailable ||
			instance.LifecycleState != core.InstanceLifecycleStateRunning && instance.LifecycleState != core.InstanceLifecycleStateStopped {
			return errors.New("known worker cleanup changed its original live instance and boot attachment")
		}
		if kind == "terminate" && (child.Terminate == nil || value(instance.Etag) != child.Terminate.IfMatch) {
			return errors.New("original termination conditional wire changed before dispatch")
		}
	}
	if err := a.lifecycle.Revalidate(a.proofContext(ctx)); err != nil {
		return err
	}
	if err := a.guard(ctx); err != nil {
		return err
	}
	if !time.Now().Before(a.lifecycle.ExpiresAt()) || a.drain == nil || !time.Now().Before(a.drain.ExpiresAt) || !time.Now().Before(wire.ExpiresAt) {
		return errors.New("original known retirement authority expired before destructive dispatch")
	}
	return ociclient.LimitAdmission(ctx, wire.ExpiresAt)
}
