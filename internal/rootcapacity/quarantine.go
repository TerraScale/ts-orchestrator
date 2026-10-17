package rootcapacity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// QuarantinePoolChild changes only unknown membership. An original protected
// child must use its independently drained retirement operation instead.
func (c *Controller) QuarantinePoolChild(ctx context.Context, call rootoci.Call, request rootoci.PoolQuarantineExpectation) (rootoci.PoolQuarantineView, error) {
	if request.Epoch == 0 || !validInstanceID(request.InstanceID) ||
		call.Operation() != "" && call.Operation() != rootoci.OperationQuarantinePoolChild {
		return rootoci.PoolQuarantineView{}, rootoci.ErrInvalid
	}
	a, close, err := c.open(ctx, call, request.Cell, request.OperationID)
	if err != nil {
		return rootoci.PoolQuarantineView{}, err
	}
	defer close()
	if request.GrantSHA256 != a.record.GrantSHA256 || request.Generation != a.record.Generation {
		return rootoci.PoolQuarantineView{}, rootoci.ErrUnauthorized
	}
	for _, child := range a.record.PoolChildren {
		if child.InstanceID == request.InstanceID {
			return rootoci.PoolQuarantineView{}, errors.New("known original child requires its independently drained retirement lifecycle")
		}
	}
	pool, exists := a.record.CapacityPools[request.PoolID]
	if !exists {
		return rootoci.PoolQuarantineView{}, errors.New("quarantine target has no protected original pool birth")
	}
	a.membership, err = a.resolver.PoolMembership(a.readContext(ctx), a.record.Cell, pool.PoolID, pool.CurrentConfigurationID)
	if err != nil {
		return rootoci.PoolQuarantineView{}, err
	}
	if !a.membership.IsVerified() || request.PurposeSHA256 != "" && request.PurposeSHA256 != a.membership.PurposeSHA256() {
		return rootoci.PoolQuarantineView{}, rootoci.ErrUnauthorized
	}
	if err := a.claimPool(ctx, pool.PoolID); err != nil {
		return rootoci.PoolQuarantineView{}, err
	}
	defer func() { _ = a.releasePool(ctx, !a.record.PoolQuarantines[a.operation].DetachedAt.IsZero()) }()
	management, err := a.factory.ComputeManagement()
	if err != nil {
		return rootoci.PoolQuarantineView{}, err
	}
	quarantine, prepared := a.record.PoolQuarantines[a.operation]
	if prepared && (quarantine.PoolID != request.PoolID || quarantine.InstanceID != request.InstanceID ||
		quarantine.ConfigurationID != pool.CurrentConfigurationID || quarantine.PurposeSHA256 != a.membership.PurposeSHA256()) {
		return rootoci.PoolQuarantineView{}, errors.New("quarantine retry changed its original member, pool, configuration or permission")
	}
	if !prepared {
		actual, err := a.originalPool(ctx, management, pool.PoolID)
		if err != nil {
			return rootoci.PoolQuarantineView{}, err
		}
		members, err := a.members(ctx, management, pool.PoolID)
		if err != nil {
			return rootoci.PoolQuarantineView{}, err
		}
		if err := exactDetachTarget(actual, members, request.InstanceID, value(actual.Size), false); err != nil {
			return rootoci.PoolQuarantineView{}, err
		}
		wire, err := prepareWire(a.detachRequest(pool.PoolID, request.InstanceID), http.MethodPost, "/instancePools/{instancePoolId}/actions/detachInstance")
		if err != nil {
			return rootoci.PoolQuarantineView{}, err
		}
		quarantine = region.PoolQuarantineRecord{OperationID: a.operation, PoolID: pool.PoolID, InstanceID: request.InstanceID,
			ConfigurationID: pool.CurrentConfigurationID, TargetFrom: value(actual.Size), PurposeSHA256: a.membership.PurposeSHA256(),
			GrantSHA256: a.record.GrantSHA256, Generation: a.record.Generation, Detach: wire}
		if a.record.PoolQuarantines == nil {
			a.record.PoolQuarantines = map[string]region.PoolQuarantineRecord{}
		}
		a.record.PoolQuarantines[a.operation] = quarantine
		if err := a.save(ctx); err != nil {
			return rootoci.PoolQuarantineView{}, err
		}
	}
	if quarantine.Detach.AcceptedAt.IsZero() {
		response, err := management.DetachInstancePoolInstance(a.writeContext(ctx, "quarantine"), a.detachRequest(quarantine.PoolID, quarantine.InstanceID))
		if err != nil {
			return rootoci.PoolQuarantineView{}, err
		}
		quarantine = a.record.PoolQuarantines[a.operation]
		acceptedWire(quarantine.Detach, response.OpcRequestId, response.OpcWorkRequestId)
		a.record.PoolQuarantines[a.operation] = quarantine
		if err := a.save(ctx); err != nil {
			return rootoci.PoolQuarantineView{}, err
		}
	}
	if quarantine.DetachedAt.IsZero() {
		complete, err := a.detachCompleted(ctx, management, quarantine.PoolID, quarantine.InstanceID, quarantine.TargetFrom, quarantine.Detach)
		if err != nil {
			return rootoci.PoolQuarantineView{}, err
		}
		if !complete {
			return rootoci.PoolQuarantineView{}, fmt.Errorf("%w: original unknown-member detach is still running", ErrPending)
		}
		if err := a.membership.Revalidate(a.readContext(ctx)); err != nil {
			return rootoci.PoolQuarantineView{}, err
		}
		quarantine.DetachedAt = time.Now().UTC()
		a.record.PoolQuarantines[a.operation] = quarantine
		if err := a.save(ctx); err != nil {
			return rootoci.PoolQuarantineView{}, err
		}
	}
	digest, err := digestValue(quarantine)
	if err != nil {
		return rootoci.PoolQuarantineView{}, err
	}
	return rootoci.PoolQuarantineView{Cell: a.record.Cell, PoolID: quarantine.PoolID, InstanceID: quarantine.InstanceID,
		OperationID: quarantine.OperationID, Stage: "quarantined", RecordSHA256: digest}, a.guard(ctx)
}

func (a *attempt) authorizeQuarantine(ctx context.Context) error {
	quarantine, exists := a.record.PoolQuarantines[a.operation]
	if !exists || quarantine.Detach == nil || !quarantine.DetachedAt.IsZero() || !a.membership.IsVerified() ||
		quarantine.PurposeSHA256 != a.membership.PurposeSHA256() {
		return errors.New("unknown detach has no exact current signed membership preparation")
	}
	if err := a.membership.Revalidate(a.readContext(ctx)); err != nil {
		return err
	}
	for _, child := range a.record.PoolChildren {
		if child.InstanceID == quarantine.InstanceID {
			return errors.New("quarantine cannot remove a known original child")
		}
	}
	management, err := a.factory.ComputeManagement()
	if err != nil {
		return err
	}
	pool, err := a.originalPool(ctx, management, quarantine.PoolID)
	if err != nil {
		return err
	}
	if value(pool.InstanceConfigurationId) != quarantine.ConfigurationID {
		return errors.New("quarantine target changed its original configuration")
	}
	members, err := a.members(ctx, management, quarantine.PoolID)
	if err != nil {
		return err
	}
	if err := exactDetachTarget(pool, members, quarantine.InstanceID, quarantine.TargetFrom, quarantine.Detach.EverUnknown); err != nil {
		return err
	}
	if err := a.guard(ctx); err != nil {
		return err
	}
	if !a.membership.IsVerified() || !time.Now().Before(a.membership.ExpiresAt()) {
		return errors.New("original signed membership authority expired before detach dispatch")
	}
	return nil
}
