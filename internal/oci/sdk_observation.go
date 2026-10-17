package oci

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// Detach only generated SDK methods; other implementations own cancellation.
func sdkObservationContext(ctx context.Context, client any) context.Context {
	switch client.(type) {
	case core.ComputeClient, *core.ComputeClient, core.BlockstorageClient, *core.BlockstorageClient,
		core.VirtualNetworkClient, *core.VirtualNetworkClient:
		return ociclient.RequestContext(ctx)
	default:
		return ctx
	}
}
