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

func (s SDKFoundations) ReconcileFoundation(ctx context.Context, plan map[string]any, operationID string, beforeWrite func(context.Context, bool) (func(), error), checkpoint func(context.Context, string, string) error) (map[string]any, error) {
	if s.Factory == nil || beforeWrite == nil || checkpoint == nil {
		return nil, errors.New("foundation SDK requires authenticated client, authority and checkpoints")
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
	provider.OperationID, provider.BeforeWrite, provider.Checkpoint = operationID, beforeWrite, checkpoint
	provider.Guard = func(ctx context.Context) error {
		release, err := beforeWrite(ctx, false)
		if err != nil {
			return err
		}
		if release == nil {
			return errors.New("foundation authority release is absent")
		}
		release()
		return nil
	}
	return provider.Reconcile(ctx, plan)
}
