package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/rootociread"
	"github.com/TerraScale/ts-orchestrator/internal/rootrelease"
)

func runManagedRuntimeRootSources(ctx context.Context, cfg Config, factory *ociclient.Factory, ownhost *managedRuntimeHost, authority *rootOCIAuthority) error {
	for ctx.Err() == nil {
		attempt, cancel := context.WithCancel(ctx)
		sources, err := openManagedRuntimeRootSources(attempt, cfg, factory, ownhost)
		if err == nil {
			defer cancel()
			defer sources.conn.Close()
			if err := authority.bindSources(sources); err != nil {
				return fmt.Errorf("bind original root runtime sources: %w", err)
			}
			observations, stopObservations := context.WithCancel(attempt)
			observationsDone := make(chan struct{})
			go func() {
				defer close(observationsDone)
				authority.runManagerRuntimeBindings(observations)
			}()
			defer func() { stopObservations(); <-observationsDone }()
			return sources.wait(attempt)
		}
		cancel()
		if errors.Is(err, errRootRuntimeSourceBinding) {
			return err
		}
		if ctx.Err() != nil {
			break
		}
		slog.WarnContext(ctx, "root runtime source admission pending", "error", err)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
	return context.Cause(ctx)
}

func openManagedRuntimeRootSources(ctx context.Context, cfg Config, factory *ociclient.Factory, ownhost *managedRuntimeHost) (*rootBoundRuntimeSources, error) {
	reader, err := rootociread.New(factory)
	if err != nil {
		return nil, err
	}
	containers, err := rootrelease.New(factory)
	if err != nil {
		return nil, err
	}
	channels, err := newRootReleaseChannels(ctx, cfg, factory, containers, ownhost.reader, ownhost.accepted)
	if err != nil {
		return nil, err
	}
	return bindRootRuntimeSources(ctx, cfg, factory, ownhost, reader, containers, channels)
}
