package mesh

import (
	"context"
	"maps"
	"time"
)

const servingProbeBudget = 300 * time.Millisecond
const servingEvery = 2 * time.Second
const servingMaxAge = 5 * time.Second

type ServingResult struct {
	Generation int64     `json:"generation"`
	Serving    bool      `json:"serving"`
	At         time.Time `json:"at"`
}

func (result ServingResult) fresh() bool {
	age := time.Since(result.At)
	return result.Serving && !result.At.IsZero() && age >= 0 && age <= servingMaxAge
}

func (n *Node) servingSnapshot() map[string]ServingResult {
	if snapshot := n.serving.Load(); snapshot != nil {
		return maps.Clone(*snapshot)
	}
	return nil
}

func (n *Node) observeServing(ctx context.Context) {
	tick := time.NewTicker(servingEvery)
	defer tick.Stop()
	for {
		results, err := n.cfg.applier.Ready(ctx)
		if err != nil {
			results = map[string]ServingResult{}
		}
		n.serving.Store(&results)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
