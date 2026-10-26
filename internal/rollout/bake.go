package rollout

import (
	"context"
	"errors"
	"maps"
	"time"
)

const BakeWindow = 5 * time.Minute

type BakeVerdict struct {
	Started  time.Time         `json:"started"`
	Finished time.Time         `json:"finished"`
	Samples  int               `json:"samples"`
	Checks   map[string]string `json:"checks"`
	Reason   string            `json:"reason,omitempty"`
}

// RunBake requires a healthy observation throughout the fixed post-readiness window.
func RunBake(ctx context.Context, probe func(context.Context) (map[string]string, error)) (BakeVerdict, error) {
	return runBake(ctx, probe, BakeWindow, 10*time.Second)
}

func runBake(ctx context.Context, probe func(context.Context) (map[string]string, error), window, poll time.Duration) (v BakeVerdict, err error) {
	start := time.Now()
	v.Started = start.UTC()
	defer func() {
		v.Finished = time.Now().UTC()
		if err != nil {
			v.Reason = err.Error()
			if v.Checks == nil {
				v.Checks = map[string]string{}
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				v.Checks["observation"] = v.Reason
			}
		}
	}()
	if probe == nil || window <= 0 || poll <= 0 {
		return v, errors.New("invalid bake observation")
	}
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		if err = ctx.Err(); err != nil {
			return v, err
		}
		sample, cancel := context.WithTimeout(ctx, poll)
		checks, failure := probe(sample)
		if sample.Err() != nil {
			failure = sample.Err()
		}
		cancel()
		v.Samples++
		v.Checks = maps.Clone(checks)
		if failure != nil {
			return v, failure
		}
		if len(checks) == 0 {
			return v, errors.New("bake has no observations")
		}
		if time.Since(start) >= window {
			return v, nil
		}
		select {
		case <-ctx.Done():
			return v, ctx.Err()
		case <-tick.C:
		}
	}
}
