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
	Region string
	Fabric *nats.Conn
	Source Source
	Apply  Apply
}

const (
	checkEvery = 10 * time.Second
	sweepEvery = 5 * time.Minute
)

type turn struct {
	swept bool
	err   error
}

func (u Updater) Run(ctx context.Context) error {
	var store *pullrelease.Store
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	finished := make(chan turn, 1)
	var stop context.CancelFunc
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	var next, sweep time.Time
	seen := map[string]string{}
	for {
		if store == nil {
			opened, err := pullrelease.Open(ctx, u.Fabric, u.Region, "apps")
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
			checking, cancel := context.WithCancel(ctx)
			stop = cancel
			due := !time.Now().Before(sweep)
			go func() { finished <- u.turn(checking, due, seen) }()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case done := <-finished:
			stop()
			stop = nil
			next = time.Now().Add(checkEvery)
			if done.swept {
				sweep = time.Now().Add(sweepEvery)
			}
			if done.err != nil && ctx.Err() == nil {
				slog.ErrorContext(ctx, "app release discovery failed", "error", done.err)
			}
		case <-tick.C:
		}
	}
}

func (u Updater) turn(ctx context.Context, due bool, seen map[string]string) turn {
	moved := []Target{}
	for _, target := range Targets {
		check, cancel := context.WithTimeout(ctx, checkEvery)
		digest, err := u.Source.Digest(check, target)
		cancel()
		if err != nil {
			slog.WarnContext(ctx, "app release tag unreadable", "service", target.Service, "error", err)
			continue
		}
		if seen[target.Service] != digest {
			seen[target.Service] = digest
			moved = append(moved, target)
		}
	}
	if due {
		return turn{swept: true, err: u.Cycle(ctx)}
	}
	return turn{err: u.cycle(ctx, moved)}
}

func (a Apply) Within(host context.Context) Apply {
	return func(ctx context.Context, service, image string, claims releasepush.Claims, progress releasepush.Progress) (json.RawMessage, error) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		defer context.AfterFunc(host, cancel)()
		return a(ctx, service, image, claims, progress)
	}
}

func (u Updater) Cycle(ctx context.Context) error {
	return u.cycle(ctx, Targets)
}

func (u Updater) cycle(ctx context.Context, targets []Target) error {
	for _, target := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		candidate, err := u.Source.Pull(ctx, target)
		if err != nil {
			slog.WarnContext(ctx, "app release refused", "service", target.Service, "error", err)
			continue
		}
		apply, cancel := context.WithTimeout(context.WithoutCancel(ctx), releasepush.HandlerWait)
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
