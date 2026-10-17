package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func runManagedRuntimeRootSources(ctx context.Context, cfg Config, factory *ociclient.Factory, ownhost *managedRuntimeHost, authority *rootOCIAuthority, backends *managedRootBackends) error {
	for ctx.Err() == nil {
		attempt, cancel := context.WithCancel(ctx)
		sources, err := bindRootRuntimeSources(attempt, cfg, factory, ownhost, backends.readers, backends.containers, backends.channels, backends.netbird)
		if err == nil {
			defer cancel()
			defer sources.conn.Close()
			if err := authority.bindSources(sources); err != nil {
				return fmt.Errorf("bind original root runtime sources: %w", err)
			}
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
