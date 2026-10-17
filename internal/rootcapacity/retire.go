package rootcapacity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// RetirePoolChild consumes one genuine protected regional drain for the exact
// original worker. Pool membership removal, instance termination and preserved
// boot deletion are three separate provider operations and retained outcomes.
func (c *Controller) RetirePoolChild(ctx context.Context, call rootoci.Call, request rootoci.PoolRetirementExpectation) (rootoci.PoolRetirementView, error) {
	if request.Child.Epoch == 0 || !entityid.Valid(request.RemovalOperationID) || request.RemovalOperationID == request.Child.OperationID ||
		request.Child.ReservationID != request.Child.OperationID || !validInstanceID(request.InstanceID) ||
		call.Operation() != "" && call.Operation() != rootoci.OperationRetirePoolChild {
		return rootoci.PoolRetirementView{}, rootoci.ErrInvalid
	}
	a, close, err := c.open(ctx, call, request.Child.Cell, request.RemovalOperationID)
	if err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	defer close()
	child, exists := a.record.PoolChildren[request.Child.OperationID]
	if !exists || !retirementSelectors(request, child) || !retirementBirthAuthority(a.record, request, child) {
		return rootoci.PoolRetirementView{}, errors.New("retirement selectors differ from the independently selected original child")
	}
	a.birthOperation = child.OperationID
	if child.Stage == region.PoolChildRetired {
		return a.retirementView(ctx, child)
	}
	if child.ReadyAt.IsZero() || child.Stage != region.PoolChildReady && child.RemovalOperationID != request.RemovalOperationID {
		return rootoci.PoolRetirementView{}, errors.New("original child has no completed birth or belongs to another removal")
	}
	ctx, cancel := context.WithDeadline(ctx, a.deadline)
	defer cancel()
	a.lifecycle, err = a.resolver.PoolLifecycle(a.proofContext(ctx), a.record.Cell, child.OperationID, child.InstanceID)
	if err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	drain, exists := a.record.PoolDrains[request.RemovalOperationID]
	if !exists {
		return rootoci.PoolRetirementView{}, errors.New("retirement has no genuine protected regional drain capture")
	}
	drainSHA, err := drain.SHA256()
	if err != nil || request.DrainSHA256 != "" && request.DrainSHA256 != drainSHA ||
		child.DrainAuthoritySHA256 != "" && child.DrainAuthoritySHA256 != drainSHA {
		return rootoci.PoolRetirementView{}, errors.Join(err, errors.New("retirement changed its original protected drain lineage"))
	}
	a.drain = &drain
	if expiry := a.lifecycle.ExpiresAt(); expiry.Before(a.deadline) {
		a.deadline = expiry
	}
	ctx, stop := context.WithDeadline(ctx, a.deadline)
	defer stop()
	if err := a.verifyRetirementDrain(ctx, child, child.Stage != region.PoolChildReady, child.Stage == region.PoolChildReady); err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	if err := a.claimPool(ctx, child.PoolID); err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	defer func() {
		_ = a.releasePool(ctx, a.record.PoolChildren[child.OperationID].Stage == region.PoolChildRetired)
	}()
	if child.Stage == region.PoolChildReady {
		pin, err := a.resolver.PinPoolDrainSource(a.proofContext(ctx), drain)
		if err != nil {
			return rootoci.PoolRetirementView{}, err
		}
		child.DrainSource = &pin
		child.RemovalOperationID, child.DrainAuthoritySHA256, child.Stage = a.operation, drainSHA, region.PoolChildDraining
		a.record.PoolChildren[child.OperationID] = child
		if err := a.save(ctx); err != nil {
			return rootoci.PoolRetirementView{}, err
		}
	}
	management, err := a.factory.ComputeManagement()
	if err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	if child.Detach == nil {
		if err := a.verifyRetirementDrain(ctx, child, true, true); err != nil {
			return rootoci.PoolRetirementView{}, err
		}
		pool, err := a.originalPool(ctx, management, child.PoolID)
		if err != nil {
			return rootoci.PoolRetirementView{}, err
		}
		members, err := a.members(ctx, management, child.PoolID)
		if err != nil {
			return rootoci.PoolRetirementView{}, err
		}
		if err := exactDetachTarget(pool, members, child.InstanceID, value(pool.Size), false); err != nil {
			return rootoci.PoolRetirementView{}, err
		}
		child.Detach, err = prepareWire(a.detachRequest(child.PoolID, child.InstanceID), http.MethodPost, "/instancePools/{instancePoolId}/actions/detachInstance")
		if err != nil {
			return rootoci.PoolRetirementView{}, err
		}
		child.Detach.ExpiresAt = a.retirementDeadline()
		child.DetachTargetFrom, child.Stage = value(pool.Size), region.PoolChildDetachPrepared
		a.record.PoolChildren[child.OperationID] = child
		if err := a.save(ctx); err != nil {
			return rootoci.PoolRetirementView{}, err
		}
	}
	if child.Detach.AcceptedAt.IsZero() {
		if err := retirementWireLive(child.Detach); err != nil {
			return rootoci.PoolRetirementView{}, err
		}
		response, err := management.DetachInstancePoolInstance(a.writeContext(ctx, "detach"), a.detachRequest(child.PoolID, child.InstanceID))
		if err != nil {
			return rootoci.PoolRetirementView{}, err
		}
		child = a.record.PoolChildren[child.OperationID]
		acceptedWire(child.Detach, response.OpcRequestId, response.OpcWorkRequestId)
		child.Stage = region.PoolChildDetaching
		a.record.PoolChildren[child.OperationID] = child
		if err := a.save(ctx); err != nil {
			return rootoci.PoolRetirementView{}, err
		}
	}
	if child.DetachedAt.IsZero() {
		complete, err := a.detachCompleted(ctx, management, child.PoolID, child.InstanceID, child.DetachTargetFrom, child.Detach)
		if err != nil {
			return rootoci.PoolRetirementView{}, err
		}
		if !complete {
			return rootoci.PoolRetirementView{}, fmt.Errorf("%w: original known-child detach is still running", ErrPending)
		}
		if err := a.verifyRetirementDrain(ctx, child, true, false); err != nil {
			return rootoci.PoolRetirementView{}, err
		}
		child.DetachedAt, child.Stage = time.Now().UTC(), region.PoolChildDetached
		a.record.PoolChildren[child.OperationID] = child
		if err := a.save(ctx); err != nil {
			return rootoci.PoolRetirementView{}, err
		}
	}
	instanceTerminal, err := a.terminateOriginal(ctx, child)
	if err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	child = a.record.PoolChildren[child.OperationID]
	if !instanceTerminal {
		return rootoci.PoolRetirementView{}, fmt.Errorf("%w: original instance is not positively terminal", ErrPending)
	}
	bootTerminal, err := a.deleteOriginalBoot(ctx, child)
	if err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	child = a.record.PoolChildren[child.OperationID]
	if !bootTerminal {
		return rootoci.PoolRetirementView{}, fmt.Errorf("%w: original preserved boot is not positively terminal", ErrPending)
	}
	if err := a.verifyRetirementDrain(ctx, child, true, false); err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	if child.InstanceTerminal == nil || child.BootTerminal == nil {
		return rootoci.PoolRetirementView{}, errors.New("original cleanup lacks retained positive instance and boot terminal evidence")
	}
	terminalAt := time.Now().UTC()
	if err := a.record.CapacityLedger.RetireResource(child.OperationID, child.InstanceID, terminalAt); err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	if err := a.record.CapacityLedger.RetireResource(child.OperationID, child.BootVolumeID, terminalAt); err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	child.InstanceRetiredAt, child.BootRetiredAt = terminalAt, terminalAt
	child.Stage, child.RetirementDrain = region.PoolChildRetired, new(drain.Clone())
	a.record.PoolChildren[child.OperationID] = child
	delete(a.record.PoolDrains, a.operation)
	if err := a.save(ctx); err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	return a.retirementView(ctx, child)
}

func retirementSelectors(request rootoci.PoolRetirementExpectation, child region.PoolChildRecord) bool {
	return request.InstanceID == child.InstanceID && request.Child.OperationID == child.OperationID && request.Child.RecipeSHA256 == child.RecipeSHA256 &&
		(request.Child.PoolID == "" || request.Child.PoolID == child.PoolID) &&
		(request.Child.ConfigurationID == "" || request.Child.ConfigurationID == child.ConfigurationID) &&
		(len(request.Child.PublicCAPEM) == 0 || bytes.Equal(request.Child.PublicCAPEM, child.PublicCAPEM)) &&
		(len(request.Child.AvailabilityDomains) == 0 || slices.Equal(request.Child.AvailabilityDomains, child.AvailabilityDomains)) &&
		(child.RemovalOperationID == "" || child.RemovalOperationID == request.RemovalOperationID)
}

// Grant selectors describe the original purchase, which remains immutable
// after a compatible signed grant update. Current cleanup authority is loaded
// separately by PoolLifecycle and the exact current regional drain source.
func retirementBirthAuthority(record region.FoundationRecord, request rootoci.PoolRetirementExpectation, child region.PoolChildRecord) bool {
	if record.CapacityLedger == nil {
		return false
	}
	matches := 0
	for _, host := range record.CapacityLedger.Hosts {
		if host.Receipt.OperationID != child.OperationID {
			continue
		}
		if host.InstanceID != child.InstanceID || host.BootVolumeID != child.BootVolumeID || !host.BornAt.Equal(child.BornAt) ||
			host.Receipt.GrantSHA256 != request.Child.GrantSHA256 || host.Receipt.GrantGeneration != request.Child.Generation ||
			host.Receipt.RecipeSHA256 != child.RecipeSHA256 {
			return false
		}
		matches++
	}
	return matches == 1
}

func (a *attempt) retirementView(ctx context.Context, child region.PoolChildRecord) (rootoci.PoolRetirementView, error) {
	digest, err := digestValue(child)
	if err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	return rootoci.PoolRetirementView{Cell: a.record.Cell, InstanceID: child.InstanceID, RemovalOperationID: child.RemovalOperationID,
		Stage: "retired", BootVolumeIDs: []string{child.BootVolumeID}, RecordSHA256: digest}, a.guard(ctx)
}

func (a *attempt) verifyRetirementDrain(ctx context.Context, child region.PoolChildRecord, consumed, destructive bool) error {
	if a.drain == nil || !a.lifecycle.IsVerified() {
		return errors.New("known retirement lacks original lifecycle and drain authority")
	}
	if err := a.lifecycle.Revalidate(a.proofContext(ctx)); err != nil {
		return err
	}
	latest, _, err := a.store.Load(a.readContext(ctx), a.record.Cell)
	if err != nil {
		return err
	}
	drain, exists := latest.PoolDrains[a.operation]
	originalSHA, err := a.drain.SHA256()
	currentSHA, currentErr := drain.SHA256()
	currentChild, known := latest.PoolChildren[child.OperationID]
	if err != nil || currentErr != nil || !exists || !known || currentSHA != originalSHA || drain.Phase != drainwire.PoolStopped ||
		drain.Child.Cell != a.record.Cell || drain.Child.BirthOperationID != child.OperationID || drain.Child.RemovalOperationID != a.operation ||
		drain.Child.InstanceID != child.InstanceID || drain.Child.PoolID != child.PoolID || drain.Child.ConfigurationID != child.ConfigurationID ||
		drain.Child.RecipeSHA256 != child.RecipeSHA256 || currentChild.InstanceID != child.InstanceID || currentChild.BootVolumeID != child.BootVolumeID ||
		consumed && (currentChild.RemovalOperationID != a.operation || currentChild.DrainAuthoritySHA256 != originalSHA) {
		return errors.Join(err, currentErr, errors.New("original protected stopped drain changed before retirement effect"))
	}
	verifyAt := time.Now().UTC()
	if !destructive {
		if !consumed {
			return errors.New("historical outcome observation requires the original already-consumed drain")
		}
		verifyAt = drain.StoppedAt
		if currentChild.DrainSource == nil {
			return errors.New("historical outcome observation lost its original signed source identity pin")
		}
		if err := a.resolver.VerifyHistoricalPoolDrainSource(a.proofContext(ctx), drain, *currentChild.DrainSource); err != nil {
			return err
		}
	}
	if err := drainwire.VerifyPoolReceiptStops(drain, verifyAt); err != nil {
		return err
	}
	if destructive {
		if err := a.resolver.VerifyCurrentPoolDrainSource(a.proofContext(ctx), drain); err != nil {
			return err
		}
	}
	return a.guard(ctx)
}

func (a *attempt) retirementDeadline() time.Time {
	deadline := a.deadline
	if a.drain != nil && a.drain.ExpiresAt.Before(deadline) {
		deadline = a.drain.ExpiresAt
	}
	return deadline
}

func retirementWireLive(wire *region.PoolWireRecord) error {
	if wire == nil || wire.ExpiresAt.IsZero() || !time.Now().Before(wire.ExpiresAt) {
		return fmt.Errorf("%w: original destructive dispatch deadline is expired; only original outcome observation remains", ErrPending)
	}
	return nil
}
