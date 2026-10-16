package region

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
)

// SDKFoundations reconciles through the authenticated regional SDK factory.
// Authority and checkpoints come from the durable regional attempt.
type SDKFoundations struct{ Factory *ociclient.Factory }

func (s SDKFoundations) ReconcileFoundation(ctx context.Context, plan map[string]any, progress FoundationProgress) (map[string]any, error) {
	if s.Factory == nil || progress.BeforeWrite == nil || progress.Checkpoint == nil || progress.CheckpointAuxiliary == nil || progress.PrepareCreate == nil {
		return nil, errors.New("foundation SDK requires authenticated client, authority and checkpoints")
	}
	if progress.ManagerAuthority != nil {
		if _, err := progress.ManagerAuthority(ctx); err != nil {
			return nil, err
		}
	}
	region, ok := plan["region"].(string)
	if !ok {
		return nil, errors.New("foundation plan requires OCI region")
	}
	tenancy, ok := plan["tenancy_id"].(string)
	if !ok {
		return nil, errors.New("foundation plan requires tenancy")
	}
	factory, err := s.Factory.ForRegion(region)
	if err != nil {
		return nil, err
	}
	provider, err := foundation.New(ctx, factory, tenancy)
	if err != nil {
		return nil, err
	}
	provider.OperationID, provider.BeforeWrite, provider.Checkpoint = progress.OperationID, progress.BeforeWrite, progress.Checkpoint
	provider.AuxiliaryIDs, provider.CheckpointAuxiliary, provider.PrepareCreate = progress.AuxiliaryIDs, progress.CheckpointAuxiliary, progress.PrepareCreate
	provider.Guard = func(ctx context.Context) error {
		guardCtx, release, err := progress.BeforeWrite(ctx, false)
		if err != nil {
			return err
		}
		if guardCtx == nil || release == nil {
			return errors.New("foundation authority release is absent")
		}
		release()
		return guardCtx.Err()
	}
	bound, err := provider.Reconcile(ctx, plan)
	if err != nil {
		return nil, err
	}
	if progress.ManagerAuthority != nil {
		if err := reconcileNetBirdManager(ctx, factory, bound, progress); err != nil {
			return nil, err
		}
	}
	return bound, nil
}
