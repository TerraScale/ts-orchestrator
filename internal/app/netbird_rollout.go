package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	local "github.com/TerraScale/ts-orchestrator/internal/netbird/agent"
)

func hostNetBird(cfg Config, public ed25519.PublicKey) func(context.Context, host.NetBirdSession) {
	settings := local.Config{Cell: cfg.NATS.Cell, Node: cfg.Host.Node, Controller: public, Directory: filepath.Join(cfg.Host.StateRoot, cfg.NATS.Cell, cfg.Host.Node, "netbird")}
	return func(ctx context.Context, session host.NetBirdSession) {
		last := ""
		for ctx.Err() == nil && !session.SessionLost() {
			status, err := local.ReadStatus(settings.Directory)
			if err == nil {
				var step host.NetBirdStep
				step, err = session.NetBirdExchange(ctx, status)
				if err == nil && len(step.Step) > 0 {
					err = local.Relay(ctx, settings, step.Step, session.FetchNetBirdBinary)
				}
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) && err.Error() != last {
				slog.WarnContext(ctx, "NetBird relay held", "node", settings.Node, "error", err)
				last = err.Error()
			} else if err == nil {
				last = ""
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}
