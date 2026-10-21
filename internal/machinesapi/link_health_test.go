package machinesapi

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type linkHealthSource func(context.Context, bool) (observability.ClusterSnapshot, error)

func (source linkHealthSource) Cluster(ctx context.Context, metrics bool) (observability.ClusterSnapshot, error) {
	return source(ctx, metrics)
}
