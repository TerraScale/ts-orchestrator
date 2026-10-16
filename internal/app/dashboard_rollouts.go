package app

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go/jetstream"
)

type dashboardRollouts struct{ store *rollout.Store }

func (source dashboardRollouts) Rollouts(ctx context.Context) ([]insights.Rollout, error) {
	return source.store.RecentRollouts(ctx)
}

func (source dashboardRollouts) Rollout(ctx context.Context, id string) (insights.Rollout, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return insights.Rollout{}, err
	}
	// Load validates the ID before reading and verifies the record's key and cell.
	record, _, err := source.store.Load(ctx, id)
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, rollout.ErrAbandonedRollout) {
		return insights.Rollout{}, dashboard.ErrRolloutNotFound
	}
	if err != nil {
		return insights.Rollout{}, err
	}
	return rollout.InsightRollout(record), nil
}

var _ dashboard.RolloutSource = dashboardRollouts{}
