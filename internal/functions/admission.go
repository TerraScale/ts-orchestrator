package functions

import (
	"context"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/release"
)

// NewWorker accepts only signed, scoped bytes from release admission. Each worker
// belongs in a separate tenant process/cgroup on an admitted function host.
func NewWorker(ctx context.Context, admitted release.VerifiedFunction) (*Worker, error) {
	if !admitted.Valid() {
		return nil, fmt.Errorf("%w: function release proof missing or expired", ErrScope)
	}
	claim := admitted.Claim()
	ctx, cancel := context.WithDeadline(ctx, admitted.ExpiresAt())
	worker, err := newWorker(ctx, Artifact{
		Manifest: Manifest{ABI: claim.ABI, TenantID: claim.TenantID, FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, Capabilities: claim.Capabilities},
		Module:   admitted.Module(),
	})
	if err != nil {
		cancel()
		return nil, err
	}
	if !admitted.Valid() || ctx.Err() != nil {
		cancel()
		_ = worker.Close(context.Background())
		return nil, fmt.Errorf("%w: function release expired during compilation", ErrScope)
	}
	closeRuntime := worker.cancel
	worker.cancel = func() { closeRuntime(); cancel() }
	return worker, nil
}
