package app

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/regionsuggest"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
)

// startRollouts opens the rollout store. knownBad, when set,
// is pointed at the store so placement admission enforces its list.
func startRollouts(ctx context.Context, cfg Config, js jetstream.JetStream, control authority.Fencer,
	fullClusterReady func() bool, knownBad *rolloutKnownBad,
) (*rollout.Store, error) {
	if js == nil {
		return nil, errors.New("rollout store requires JetStream")
	}
	store, _, err := retryControllerOpen(ctx, "open rollout store", fullClusterReady, false,
		func(attempt context.Context) (*rollout.Store, error) {
			return rollout.OpenStore(attempt, js, cfg.NATS.Cell, cfg.NATS.Replicas, control)
		}, nil)
	if err != nil {
		return nil, err
	}
	if knownBad != nil {
		knownBad.store.Store(store)
	}
	return store, nil
}

// rolloutKnownBad refuses placement admission until the mandatory rollout store opens.
type rolloutKnownBad struct {
	store atomic.Pointer[rollout.Store]
}

func newRolloutKnownBad() *rolloutKnownBad { return &rolloutKnownBad{} }

func (k *rolloutKnownBad) IsKnownBad(ctx context.Context, digest string) (bool, error) {
	store := k.store.Load()
	if store == nil {
		return false, errors.New("the rollout store is not open yet")
	}
	return store.IsKnownBad(ctx, digest)
}

// startRegionSuggestions suggests regions on the global home's leader. Only the
// home holds the global authority, so every other region starts nothing. The
// store opens in the background and the controller does not wait for it; a
// failure is logged, not fatal.
func startRegionSuggestions(ctx context.Context, cfg Config, js jetstream.JetStream, global *globalControl,
	rollups func() []globalview.Region, fullClusterReady func() bool, page *capacityPage,
) {
	if global == nil || global.authority == nil {
		return
	}
	if _, ok := catalog.LookupName(cfg.NATS.Cell); !ok {
		slog.Error("region suggestions need the home region's cell", observability.ComponentKey, "regionsuggest",
			"cell", cfg.NATS.Cell)
		return
	}
	go func() {
		store, _, err := retryControllerOpen(ctx, "open region suggestion store", fullClusterReady, false,
			func(attempt context.Context) (*regionsuggest.Store, error) {
				return regionsuggest.OpenStore(attempt, js, cfg.NATS.Replicas, global.authority)
			}, nil)
		if err != nil {
			if ctx.Err() == nil {
				slog.Error("region suggestions did not start", observability.ComponentKey, "regionsuggest", "error", err)
			}
			return
		}
		page.suggestions.Store(store)
		runner := &regionsuggest.Runner{Home: cfg.NATS.Cell, Rollups: rollups,
			Roster: func(ctx context.Context) (globalcontrol.Roster, error) {
				roster, _, err := global.reader.Roster(ctx)
				return roster, err
			},
			Capacity: func(ctx context.Context) (budget.Capacity, bool, error) {
				return budget.ReadCapacity(ctx, global.reader)
			},
			State: store}
		ticker := time.NewTicker(regionsuggest.Interval)
		defer ticker.Stop()
		lastError := ""
		for {
			if snapshot := global.authority.Current(); snapshot.CanMutate() {
				if _, err := runner.Suggest(ctx, snapshot.Epoch, time.Now()); err != nil && ctx.Err() == nil {
					if text := err.Error(); text != lastError {
						slog.Error("region suggestion failed", observability.ComponentKey, "regionsuggest", "error", text)
						lastError = text
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
