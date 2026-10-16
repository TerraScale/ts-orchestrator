package rollout

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/nats-io/nats.go/jetstream"
)

// RecentRollouts reads the newest ReleaseHistory generations' recorded stages,
// plus the active rollout. Exact older records remain readable through Load.
func (s *Store) RecentRollouts(ctx context.Context) ([]insights.Rollout, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	desired, _, err := s.Desired(ctx)
	if err != nil {
		return nil, err
	}
	active, _, ok, err := s.Active(ctx)
	if err != nil {
		return nil, err
	}
	var records []insights.Rollout
	seen := make(map[string]bool)
	if ok {
		records = append(records, InsightRollout(active))
		seen[active.RolloutID] = true
	}
	newest := desired.Generation()
	for offset := range min(newest, uint64(ReleaseHistory)) {
		for _, domain := range []string{ControllerReleaseDomain, HostReleaseDomain} {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			id := entityid.Derive(domain, ReleaseRolloutID(newest-offset))
			if seen[id] {
				continue
			}
			record, _, err := s.Load(ctx, id)
			if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, ErrAbandonedRollout) {
				continue
			}
			if err != nil {
				return nil, err
			}
			records = append(records, InsightRollout(record))
			seen[id] = true
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(records, func(a, b insights.Rollout) int {
		return cmp.Or(b.PhaseStarted.Compare(a.PhaseStarted), cmp.Compare(a.ID, b.ID))
	})
	return records, nil
}
