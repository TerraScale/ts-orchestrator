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
			original, stopOriginal := context.WithDeadline(attempt, sources.deadline)
			defer stopOriginal()
			lifetime, stopOCIR, err := startManagedRuntimeOCIR(original, backends.foundation, sources.guard)
			if err != nil {
				return fmt.Errorf("initialize root registry credentials before runtime admission: %w", err)
			}
			defer stopOCIR()
			if err := authority.bindSources(sources); err != nil {
				return fmt.Errorf("bind original root runtime sources: %w", err)
			}
			return errors.Join(sources.wait(lifetime), context.Cause(lifetime))
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
