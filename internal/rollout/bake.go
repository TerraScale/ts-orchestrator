package rollout

import (
	"context"
	"errors"
	"maps"
	"time"
)

const BakeWindow = 5 * time.Minute
const DependencyRecoveryWindow = 30 * time.Second

// DependencyFailure distinguishes swap-induced dependency recovery from a
// candidate or storage regression, which must always hold immediately.
type DependencyFailure struct{ Service, Status string }

func (f *DependencyFailure) Error() string {
	return "bake " + f.Service + " readiness: " + f.Status
}

func recoveringDependency(err error) bool {
	switch failure := err.(type) {
	case *DependencyFailure:
		return (failure.Service == "ts-auth" || failure.Service == "ts-dashboard") &&
			(failure.Status == "HTTP 503" || failure.Status == "request-failed" || failure.Status == "dependency-unavailable-or-missing")
	case interface{ Unwrap() []error }:
		if len(failure.Unwrap()) == 0 {
			return false
		}
		for _, cause := range failure.Unwrap() {
			if !recoveringDependency(cause) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return recoveringDependency(failure.Unwrap())
	}
	return false
}

type BakeVerdict struct {
	Started         time.Time         `json:"started"`
	Finished        time.Time         `json:"finished"`
	Samples         int               `json:"samples"`
	Checks          map[string]string `json:"checks"`
	Reason          string            `json:"reason,omitempty"`
	HealthySince    time.Time         `json:"healthySince"`
	RecoverySamples int               `json:"recoverySamples,omitempty"`
	RecoveryChecks  map[string]string `json:"recoveryChecks,omitempty"`
}

// RunBake allows bounded initial dependency recovery, then requires a full
// healthy window. Candidate and storage failures never receive this allowance.
func RunBake(ctx context.Context, probe func(context.Context) (map[string]string, error)) (BakeVerdict, error) {
	return runBake(ctx, probe, BakeWindow, 10*time.Second)
}

func runBake(ctx context.Context, probe func(context.Context) (map[string]string, error), window, poll time.Duration) (v BakeVerdict, err error) {
	start := time.Now()
	v.Started = start.UTC()
	healthySince := start
	v.HealthySince = start.UTC()
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
			if !recoveringDependency(failure) || time.Since(start) >= DependencyRecoveryWindow {
				return v, failure
			}
			v.RecoverySamples++
			v.RecoveryChecks = maps.Clone(checks)
			healthySince, v.HealthySince = time.Time{}, time.Time{}
		} else if len(checks) == 0 {
			return v, errors.New("bake has no observations")
		} else {
			if healthySince.IsZero() {
				healthySince = time.Now()
				v.HealthySince = healthySince.UTC()
			}
			if time.Since(healthySince) >= window {
				return v, nil
			}
		}
		select {
		case <-ctx.Done():
			return v, ctx.Err()
		case <-tick.C:
		}
	}
}
