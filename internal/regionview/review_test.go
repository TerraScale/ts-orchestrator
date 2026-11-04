package regionview

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type failingCluster struct{}

func (failingCluster) Cluster(context.Context, bool) (observability.ClusterSnapshot, error) {
	return observability.ClusterSnapshot{}, errors.New("no responders")
}

type staticSnapshot struct{ snapshot observability.MemberSnapshot }

func (source staticSnapshot) Snapshot(context.Context, bool) (observability.MemberSnapshot, error) {
	return source.snapshot, nil
}
