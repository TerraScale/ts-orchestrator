package rootcapacity

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// PreparePoolRetirement describes a live original worker under current cleanup
// scope. It grants no runtime admission and performs no protected/provider write.
func (c *Controller) PreparePoolRetirement(ctx context.Context, call rootoci.Call, request rootoci.PoolRetirementSelector) (rootoci.PoolRetirementPreparation, error) {
	fail := func(err error) (rootoci.PoolRetirementPreparation, error) {
		return rootoci.PoolRetirementPreparation{}, err
	}
	if c == nil || c.factory == nil || c.store == nil || ctx == nil || call.Guard(ctx) != nil ||
		request.Cell == "" || request.Cell != strings.ToUpper(request.Cell) || !validInstanceID(request.InstanceID) ||
		call.Operation() != "" && call.Operation() != rootoci.OperationPreparePoolRetirement ||
		call.Expected().Cell != "" && call.Expected().Cell != request.Cell {
		return fail(rootoci.ErrUnauthorized)
	}
	store, err := c.resolver.ProtectedCapacityReaderStore(c.factory)
	if err != nil || store != c.store {
		return fail(errors.Join(err, rootoci.ErrPoolChildUnverified))
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	defer cancel()
	readCtx := ociclient.RequestContext(ociclient.WithRequestGuard(ociclient.CheckpointContext(ctx), call.Guard))
	record, err := c.resolver.Resolve(readCtx, request.Cell)
	if err != nil {
		return fail(err)
	}
	child, receipt, err := retirementPreparationBirth(record, request.InstanceID)
	if err != nil || call.Expected().OperationID != "" && call.Expected().OperationID != child.OperationID ||
		call.Expected().GrantSHA256 != "" && call.Expected().GrantSHA256 != record.GrantSHA256 {
		return fail(errors.Join(err, rootoci.ErrPoolChildUnverified))
	}
	factory, err := c.factory.ForRegion(record.OCIRegion)
	if err != nil {
		return fail(err)
	}
	// The existing observation marker permanently excludes writer/lease paths.
	observation := rootoci.PoolChildObservation{Cell: record.Cell, InstanceID: child.InstanceID}
	a := &attempt{call: call, resolver: c.resolver, store: store, factory: factory, record: record, deadline: call.Deadline(),
		operation: child.OperationID, birthOperation: child.OperationID, observation: &observation}
	a.lifecycle, err = a.resolver.PoolLifecycle(a.proofContext(ctx), record.Cell, child.OperationID, child.InstanceID)
	if err != nil {
		return fail(err)
	}
	binding := a.lifecycle.Binding()
	if binding.GrantSHA256 != record.GrantSHA256 || binding.Generation != record.Generation {
		return fail(rootoci.ErrPoolChildUnverified)
	}
	if a.lifecycle.ExpiresAt().Before(a.deadline) {
		a.deadline = a.lifecycle.ExpiresAt()
	}
	ctx, stop := context.WithDeadline(ctx, a.deadline)
	defer stop()
	if err := a.readRetirementPreparation(ctx, child); err != nil {
		return fail(err)
	}
	latest, _, err := store.Load(a.readContext(ctx), record.Cell)
	if err != nil {
		return fail(err)
	}
	originalSHA, err := digestValue(record)
	if err != nil {
		return fail(err)
	}
	latestSHA, err := digestValue(latest)
	if err != nil || latestSHA != originalSHA {
		return fail(errors.Join(err, errors.New("protected original worker changed during retirement preparation")))
	}
	if err := a.lifecycle.Revalidate(a.proofContext(ctx)); err != nil {
		return fail(err)
	}
	if err := a.guard(ctx); err != nil || !time.Now().Before(a.deadline) {
		return fail(errors.Join(err, rootoci.ErrUnauthorized))
	}
	return rootoci.PoolRetirementPreparation{CurrentGrantSHA256: binding.GrantSHA256, CurrentGeneration: binding.Generation,
		Node: child.Node, Retirement: rootoci.PoolRetirementExpectation{
			Child: rootoci.PoolChildExpectation{Cell: record.Cell, OperationID: child.OperationID, ReservationID: child.OperationID,
				RecipeSHA256: child.RecipeSHA256, PoolID: child.PoolID, ConfigurationID: child.ConfigurationID,
				GrantSHA256: receipt.GrantSHA256, Generation: receipt.GrantGeneration, Epoch: child.BirthEpoch}, InstanceID: child.InstanceID}}, nil
}

func retirementPreparationBirth(record region.FoundationRecord, instanceID string) (region.PoolChildRecord, capacityledger.Receipt, error) {
	fail := func() (region.PoolChildRecord, capacityledger.Receipt, error) {
		return region.PoolChildRecord{}, capacityledger.Receipt{}, rootoci.ErrPoolChildUnverified
	}
	var child region.PoolChildRecord
	for key, candidate := range record.PoolChildren {
		if candidate.InstanceID != instanceID {
			continue
		}
		if child.OperationID != "" || key != candidate.OperationID || !entityid.Valid(key) {
			return fail()
		}
		child = candidate
	}
	if record.CapacityLedger == nil || child.OperationID == "" || child.Stage != region.PoolChildReady || child.BirthEpoch == 0 || !naming.IsNode(child.Node, record.Cell) ||
		child.Launch == nil || child.Launch.AcceptedAt.IsZero() || child.Attach == nil || child.Attach.AcceptedAt.IsZero() ||
		child.Attach.WorkCompletedAt.IsZero() || child.ReadyAt.Before(child.Attach.WorkCompletedAt) ||
		!child.BornAt.Equal(child.Launch.AcceptedAt) || child.RemovalOperationID != "" || child.InstanceTerminal != nil || child.BootTerminal != nil {
		return fail()
	}
	var original capacityledger.Receipt
	for _, host := range record.CapacityLedger.Hosts {
		if host.Receipt.OperationID != child.OperationID {
			continue
		}
		if original.OperationID != "" || host.InstanceID != child.InstanceID || host.BootVolumeID != child.BootVolumeID ||
			host.RequestSHA256 != child.Launch.RequestSHA256 || !host.StartedAt.Equal(child.Launch.FirstAttemptAt) ||
			!host.BornAt.Equal(child.BornAt) || !host.InstanceRetiredAt.IsZero() || !host.BootRetiredAt.IsZero() {
			return fail()
		}
		original = host.Receipt
	}
	pool, known := record.CapacityPools[child.PoolID]
	if !known || original.Validate() != nil || original.RecipeSHA256 != child.RecipeSHA256 || original.TenancyID != record.TenancyID ||
		original.Quote.Cell != record.Cell || original.Quote.CompartmentID != pool.CompartmentID || original.Quote.Shape != pool.Shape ||
		original.Quote.OCPUs != 2 || original.Quote.MemoryGB != 12 || original.Quote.BootGB != 50 {
		return fail()
	}
	return child, original, nil
}

func (a *attempt) readRetirementPreparation(ctx context.Context, child region.PoolChildRecord) error {
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
	if err := exactDetachTarget(pool, members, child.InstanceID, value(pool.Size), false); err != nil {
		return err
	}
	member, err := management.GetInstancePoolInstance(a.readContext(ctx), core.GetInstancePoolInstanceRequest{InstancePoolId: new(child.PoolID), InstanceId: new(child.InstanceID)})
	if err != nil {
		return err
	}
	if value(member.Id) != child.InstanceID || value(member.InstancePoolId) != child.PoolID || value(member.InstanceConfigurationId) != child.ConfigurationID ||
		value(member.CompartmentId) != a.lifecycle.Binding().CompartmentID || value(member.AvailabilityDomain) != child.AvailabilityDomain ||
		member.LifecycleState != core.InstancePoolInstanceLifecycleStateActive {
		return errors.New("retirement preparation lost exact active original pool membership")
	}
	instance, err := a.originalInstance(ctx, child)
	if err != nil {
		return err
	}
	if instance.LifecycleState != core.InstanceLifecycleStateRunning && instance.LifecycleState != core.InstanceLifecycleStateStopped {
		return errors.New("retirement preparation target is not a live original instance")
	}
	architecture, err := catalog.ShapeArchitecture(value(instance.ShapeConfig.ProcessorDescription))
	if err != nil || architecture != a.lifecycle.Binding().Architecture {
		return errors.Join(err, errors.New("retirement preparation actual processor changed original architecture"))
	}
	boot, err := a.originalBoot(ctx, child)
	if err != nil {
		return err
	}
	if boot.LifecycleState != core.BootVolumeLifecycleStateAvailable {
		return errors.New("retirement preparation original boot is not available and attached")
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
	if value(attachments.OpcNextPage) != "" || len(attachments.Items) > 64 {
		return errors.New("retirement preparation boot inventory exceeds its finite original scope")
	}
	attached := false
	for _, attachment := range attachments.Items {
		if value(attachment.BootVolumeId) != child.BootVolumeID || value(attachment.CompartmentId) != a.lifecycle.Binding().CompartmentID ||
			value(attachment.AvailabilityDomain) != child.AvailabilityDomain {
			return errors.New("retirement preparation boot attachment returned conflicting scope")
		}
		if attachment.LifecycleState == core.BootVolumeAttachmentLifecycleStateDetached {
			continue
		}
		if attached || value(attachment.Id) != child.BootAttachmentID || value(attachment.InstanceId) != child.InstanceID ||
			attachment.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached {
			return errors.New("retirement preparation original boot has another or unsettled attachment")
		}
		attached = true
	}
	if !attached {
		return errors.New("retirement preparation lacks the exact original boot attachment")
	}
	network, err := a.factory.Network()
	if err != nil {
		return err
	}
	vnics, err := compute.ListVnicAttachments(a.readContext(ctx), core.ListVnicAttachmentsRequest{
		CompartmentId: new(a.lifecycle.Binding().CompartmentID), InstanceId: new(child.InstanceID)})
	if err != nil {
		return err
	}
	if value(vnics.OpcNextPage) != "" || len(vnics.Items) > 64 {
		return errors.New("retirement preparation network inventory exceeds its finite original scope")
	}
	primary := false
	for _, attachment := range vnics.Items {
		if value(attachment.InstanceId) != child.InstanceID || value(attachment.CompartmentId) != a.lifecycle.Binding().CompartmentID {
			return errors.New("retirement preparation network attachment returned conflicting original scope")
		}
		if attachment.LifecycleState == core.VnicAttachmentLifecycleStateDetached {
			continue
		}
		if primary || attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached || value(attachment.SubnetId) != child.SubnetID || value(attachment.VnicId) == "" {
			return errors.New("retirement preparation target lost its single original subnet attachment")
		}
		actual, err := network.GetVnic(a.readContext(ctx), core.GetVnicRequest{VnicId: attachment.VnicId})
		if err != nil {
			return err
		}
		if value(actual.Id) != value(attachment.VnicId) || actual.LifecycleState != core.VnicLifecycleStateAvailable || !value(actual.IsPrimary) ||
			value(actual.SubnetId) != child.SubnetID || value(actual.AvailabilityDomain) != child.AvailabilityDomain ||
			value(actual.PublicIp) != "" || actual.SkipSourceDestCheck == nil || *actual.SkipSourceDestCheck {
			return errors.New("retirement preparation primary network differs from exact original private topology")
		}
		primary = true
	}
	if !primary {
		return errors.New("retirement preparation lacks its original primary subnet attachment")
	}
	return a.guard(ctx)
}
