package apppull

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats.go"
)

type Apply func(context.Context, string, string, releasepush.Claims, releasepush.Progress) (json.RawMessage, error)

type Updater struct {
	Self   string
	Fabric *nats.Conn
	Source Source
	Apply  Apply
}

func (u Updater) Run(ctx context.Context) error {
	var store *pullrelease.Store
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	finished := make(chan error, 1)
	var stop context.CancelFunc
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	var next time.Time
	for {
		if store == nil {
			opened, err := pullrelease.Open(ctx, u.Fabric, "apps")
			if err != nil {
				slog.ErrorContext(ctx, "app rollout store unavailable", "error", err)
			}
			store = opened
		}
		leading := false
		if store != nil {
			owned, err := store.Lead(ctx, u.Self)
			if err != nil {
				slog.ErrorContext(ctx, "app rollout lease not renewed", "error", err)
			}
			leading = owned && err == nil
		}
		if !leading && stop != nil {
			stop()
		}
		if leading && stop == nil && !time.Now().Before(next) {
			turn, cancel := context.WithCancel(ctx)
			stop = cancel
			go func() { finished <- u.Cycle(turn) }()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-finished:
			stop()
			stop = nil
			next = time.Now().Add(pullrelease.DefaultPoll)
			if err != nil && ctx.Err() == nil {
				slog.ErrorContext(ctx, "app release discovery failed", "error", err)
			}
		case <-tick.C:
		}
	}
}

func (u Updater) Cycle(ctx context.Context) error {
	for _, target := range Targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		candidate, err := u.Source.Pull(ctx, target)
		if err != nil {
			slog.WarnContext(ctx, "app release refused", "service", target.Service, "error", err)
			continue
		}
		apply, cancel := context.WithTimeout(ctx, releasepush.HandlerWait)
		_, err = u.Apply(apply, target.Service, candidate.Image, candidate.Claims, progress{ctx, target.Service})
		cancel()
		if err != nil {
			slog.ErrorContext(ctx, "pulled app release failed", "service", target.Service, "image", candidate.Image, "error", err)
		}
	}
	return nil
}

type progress struct {
	ctx     context.Context
	service string
}

func (p progress) Deadline(deadline time.Time) {
	slog.InfoContext(p.ctx, "pulled app rollout deadline", "service", p.service, "deadline", deadline)
}
func (p progress) Event(event string) {
	slog.InfoContext(p.ctx, "pulled app rollout progress", "service", p.service, "event", event)
}
