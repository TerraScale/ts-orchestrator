package app

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// instancePrincipal is ociclient.InstancePrincipal bounded by ctx, so a
// stopping controller is not held by the metadata fetch. shortcut: the
// fetch ignores ctx and finishes unobserved, upgrade when ociclient takes one.
func instancePrincipal(ctx context.Context, region string) (*ociclient.Factory, error) {
	type answer struct {
		factory *ociclient.Factory
		err     error
	}
	done := make(chan answer, 1)
	go func() {
		factory, err := ociclient.InstancePrincipal(region)
		done <- answer{factory, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-done:
		return result.factory, result.err
	}
}
