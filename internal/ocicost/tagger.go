package ocicost

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// TagAPI lists a region's resources and stamps freeform tags on one.
type TagAPI interface {
	Resources(ctx context.Context) ([]Resource, error)
	// Retag merges tags into the resource's freeform tags. It returns
	// ErrChanged when the resource changed between its read and the update,
	// and ErrNotPermitted when the principal may not update it.
	Retag(ctx context.Context, resource Resource, tags map[string]string) error
}

var (
	ErrChanged      = errors.New("OCI resource changed during the tag pass")
	ErrNotPermitted = errors.New("not permitted to tag the OCI resource")
)

// TagResult counts one pass.
type TagResult struct {
	Stamped, Changed, NotPermitted, Untagged int
}

// passTimeout bounds one pass over every resource in the region.
const passTimeout = 10 * time.Minute

// Tagger keeps the region's billable resources tagged with their region and
// component, so the Usage API can split their cost. Only the regional
// authority leader runs a pass.
type Tagger struct {
	Cell    string
	Leader  func() bool
	Connect func(ctx context.Context) (TagAPI, error)
	Now     func() time.Time

	api     TagAPI
	failure string
}

// Run tags once an hour until ctx ends, then returns nil.
func (t *Tagger) Run(ctx context.Context) error {
	for {
		timer := time.NewTimer(t.step(ctx))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// step does one tag pass and returns how long to wait before the next.
func (t *Tagger) step(ctx context.Context) time.Duration {
	if !t.Leader() {
		return followInterval
	}
	if t.api == nil {
		api, err := t.Connect(ctx)
		if err != nil {
			t.fail(err)
			return retryInterval
		}
		t.api = api
	}
	passCtx, cancel := context.WithTimeout(ctx, passTimeout)
	result, err := Pass(passCtx, t.api, t.Cell, t.now())
	cancel()
	if err != nil {
		t.fail(err)
		return retryInterval
	}
	if result.Stamped+result.Changed+result.NotPermitted > 0 {
		slog.Info("OCI cost tag pass", observability.ComponentKey, "ocicost", "stamped", result.Stamped,
			"changed", result.Changed, "not_permitted", result.NotPermitted, "untagged", result.Untagged)
	}
	t.recovered()
	return Interval
}

// Pass plans and applies one pass with api.
func Pass(ctx context.Context, api TagAPI, cell string, now time.Time) (TagResult, error) {
	resources, err := api.Resources(ctx)
	if err != nil {
		return TagResult{}, fmt.Errorf("list OCI resources for tags: %w", err)
	}
	stamps, untagged := PlanTags(cell, resources, now)
	result, err := applyStamps(ctx, api, stamps)
	result.Untagged = len(untagged)
	return result, err
}

// applyStamps retags each planned resource. A resource that changed or that
// the principal may not update is counted, not fatal; any other error stops
// the pass with the counts so far.
func applyStamps(ctx context.Context, api TagAPI, stamps []Stamp) (TagResult, error) {
	var result TagResult
	for _, stamp := range stamps {
		switch err := api.Retag(ctx, stamp.Resource, stamp.Tags); {
		case errors.Is(err, ErrChanged):
			result.Changed++
		case errors.Is(err, ErrNotPermitted):
			result.NotPermitted++
		case err != nil:
			return result, fmt.Errorf("tag OCI %s %s: %w", stamp.Resource.Type, stamp.Resource.Name, err)
		default:
			result.Stamped++
		}
	}
	return result, nil
}

func (t *Tagger) now() time.Time {
	if t.Now == nil {
		return time.Now()
	}
	return t.Now()
}

// fail logs once per distinct error, so a long outage does not flood the log.
func (t *Tagger) fail(err error) {
	if err.Error() != t.failure {
		slog.Warn("OCI cost tags not applied", observability.ComponentKey, "ocicost", "error", err)
	}
	t.failure = err.Error()
}

func (t *Tagger) recovered() {
	if t.failure != "" {
		slog.Info("OCI cost tags are current again", observability.ComponentKey, "ocicost")
	}
	t.failure = ""
}
