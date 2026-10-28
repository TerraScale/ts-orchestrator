package rollout

import (
	"context"
	"errors"
	"maps"
	"time"
)

const BakeWindow = 30 * time.Second
const DependencyRecoveryWindow = 30 * time.Second
const MaxBakeWindow = 2*BakeWindow + DependencyRecoveryWindow

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

// RunBake allows bounded dependency recovery, then requires a full
// healthy window. Candidate and storage failures never receive this allowance.
func RunBake(ctx context.Context, probe func(context.Context) (map[string]string, error)) (BakeVerdict, error) {
	return runBake(ctx, probe, BakeWindow, 2*time.Second)
}

func runBake(ctx context.Context, probe func(context.Context) (map[string]string, error), window, poll time.Duration) (v BakeVerdict, err error) {
	start := time.Now()
	v.Started = start.UTC()
	healthySince := start
	var failureSince time.Time
	var lastFailure error
	var recovery <-chan time.Time
	var recoveryTimer *time.Timer
	defer func() {
		if recoveryTimer != nil {
			recoveryTimer.Stop()
		}
	}()
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
	// A late dependency rollout can restart the healthy window. Repeated
	// interruptions must not extend a regional rollout indefinitely.
	ctx, stop := context.WithTimeout(ctx, 2*window+DependencyRecoveryWindow)
	defer stop()
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		if err = ctx.Err(); err != nil {
			return v, err
		}
		if !failureSince.IsZero() && time.Since(failureSince) >= DependencyRecoveryWindow {
			return v, lastFailure
		}
		deadline := time.Now().Add(poll)
		if !failureSince.IsZero() && failureSince.Add(DependencyRecoveryWindow).Before(deadline) {
			deadline = failureSince.Add(DependencyRecoveryWindow)
		}
		sample, cancel := context.WithDeadline(ctx, deadline)
		checks, failure := probe(sample)
		if sample.Err() != nil {
			failure = sample.Err()
		}
		if ctx.Err() == nil && !failureSince.IsZero() && time.Since(failureSince) >= DependencyRecoveryWindow {
			failure = lastFailure
		}
		cancel()
		v.Samples++
		v.Checks = maps.Clone(checks)
		if failure != nil {
			if failureSince.IsZero() {
				failureSince = time.Now()
				recoveryTimer = time.NewTimer(DependencyRecoveryWindow)
				recovery = recoveryTimer.C
			}
			if !recoveringDependency(failure) || time.Since(failureSince) >= DependencyRecoveryWindow {
				return v, failure
			}
			v.RecoverySamples++
			v.RecoveryChecks = maps.Clone(checks)
			lastFailure = failure
			healthySince, v.HealthySince = time.Time{}, time.Time{}
		} else if len(checks) == 0 {
			return v, errors.New("bake has no observations")
		} else {
			if recoveryTimer != nil {
				recoveryTimer.Stop()
			}
			recovery = nil
			failureSince = time.Time{}
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
		case <-recovery:
			if ctx.Err() != nil {
				return v, ctx.Err()
			}
			return v, lastFailure
		case <-tick.C:
		}
	}
}
