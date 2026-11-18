package edge

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

const (
	regionalRefusalBase   = 30 * time.Second
	regionalRefusalMax    = 10 * time.Minute
	regionalRefusalReport = 2 * time.Minute
)

type regionalRefusal struct {
	code string
	err  error
}

func (r *regionalRefusal) Error() string { return r.err.Error() }

func (r *regionalRefusal) Unwrap() error { return r.err }

type regionalBackoff struct {
	task     string
	refusal  *regionalRefusal
	failures int
	next     time.Time
	seen     time.Time
}

var regionalRefusals = struct {
	sync.Mutex
	sources map[string]regionalBackoff
}{sources: map[string]regionalBackoff{}}

func regionalRefusalDelay(failures int) time.Duration {
	return min(regionalRefusalBase<<min(max(failures-1, 0), 5), regionalRefusalMax)
}

func regionalRefusalPending(source, task string, now time.Time) error {
	regionalRefusals.Lock()
	defer regionalRefusals.Unlock()
	backoff, ok := regionalRefusals.sources[source]
	if !ok || backoff.task != task {
		return nil
	}
	backoff.seen = now
	regionalRefusals.sources[source] = backoff
	if !now.Before(backoff.next) {
		return nil
	}
	return regionalRefusalError(backoff, now)
}

func regionalRefusalRecord(source, task string, err error, now time.Time) error {
	regionalRefusals.Lock()
	defer regionalRefusals.Unlock()
	if err == nil {
		delete(regionalRefusals.sources, source)
		return nil
	}
	var refusal *regionalRefusal
	if !errors.As(err, &refusal) {
		return err
	}
	backoff := regionalRefusals.sources[source]
	if backoff.task != task {
		backoff = regionalBackoff{task: task}
	}
	backoff.failures++
	backoff.refusal = refusal
	backoff.next = now.Add(regionalRefusalDelay(backoff.failures))
	backoff.seen = now
	regionalRefusals.sources[source] = backoff
	return regionalRefusalError(backoff, now)
}

func regionalRefusalError(backoff regionalBackoff, now time.Time) error {
	return fmt.Errorf("regional handoff refused (%d in a row): %w; next attempt in %s", backoff.failures, backoff.refusal, backoff.next.Sub(now).Round(time.Second))
}

func WriteRegionalDrainMetrics(w io.Writer) {
	regionalRefusals.Lock()
	defer regionalRefusals.Unlock()
	now := time.Now()
	for _, source := range slices.Sorted(maps.Keys(regionalRefusals.sources)) {
		backoff := regionalRefusals.sources[source]
		if now.Sub(backoff.seen) > regionalRefusalReport {
			continue
		}
		observability.WriteGauge(w, observability.Series("ts_orch_regional_drain_refused", "source", source, "code", backoff.refusal.code), 1)
	}
}
