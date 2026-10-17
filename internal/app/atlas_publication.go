package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/atlas"
	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// atlasPublication schedules the fixed root operation without holding a key.
type atlasPublication struct {
	cell      string
	config    func() *atlas.Config
	authority authority.Fencer
	since     time.Time
	alerted   bool
}

func (l *atlasPublication) Run(ctx context.Context) error {
	ticker := time.NewTicker(atlas.Interval)
	defer ticker.Stop()
	for {
		l.tick(ctx, time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (l *atlasPublication) tick(parent context.Context, now time.Time) {
	snapshot := l.authority.Current()
	if l.config() == nil || !snapshot.CanMutate() {
		l.since, l.alerted = time.Time{}, false
		return
	}
	ctx, cancel := context.WithTimeout(parent, atlas.Interval)
	defer cancel()
	client := rootoci.NewClient(rootoci.Expectations{Cell: l.cell, Epoch: snapshot.Epoch})
	defer client.Close()
	var receipt rootoci.AtlasTopologyReceipt
	err := l.authority.Guard(ctx, snapshot.Epoch)
	if err == nil {
		receipt, err = client.ReconcileAtlasTopology(ctx)
	}
	current := l.authority.Current()
	if !current.CanMutate() || current.Epoch != snapshot.Epoch ||
		errors.Is(err, authority.ErrNotLeader) || errors.Is(err, authority.ErrFenced) ||
		err == nil && receipt.State == rootoci.AtlasTopologyUnconfigured {
		l.since, l.alerted = time.Time{}, false
		return
	}
	if err == nil {
		if l.alerted {
			slog.InfoContext(parent, "Atlas topology is current again", observability.ComponentKey, "atlas", observability.EventKey, true)
		}
		l.since, l.alerted = now, false
		return
	}
	if l.since.IsZero() {
		l.since = now
	}
	slog.WarnContext(parent, "Atlas publish failed", observability.ComponentKey, "atlas", "error", err)
	if !l.alerted && now.Sub(l.since) >= atlas.StaleAfter {
		l.alerted = true
		slog.ErrorContext(parent, "ALERT Atlas topology is stale: no publish succeeded", observability.ComponentKey, "atlas",
			"since", l.since, "error", err, observability.EventKey, true)
	}
}
