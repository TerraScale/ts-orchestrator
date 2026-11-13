package rollout

import (
	"context"
	"errors"
	"maps"
	"strings"
	"time"
)

const BakeWindow = 30 * time.Second
const MaxBakeWindow = 10 * time.Minute
const BakeFailureDuration = 15 * time.Second
const sampleBudget = 5 * time.Second

type DependencyFailure struct{ Service, Status string }

func (f *DependencyFailure) Error() string {
	return "bake " + f.Service + " readiness: " + f.Status
}

type BakeVerdict struct {
	Started             time.Time            `json:"started"`
	FirstSample         time.Time            `json:"firstSample"`
	Finished            time.Time            `json:"finished"`
	Samples             int                  `json:"samples"`
	Checks              map[string]string    `json:"checks"`
	Reason              string               `json:"reason,omitempty"`
	HealthySince        time.Time            `json:"healthySince"`
	FailedSamples       int                  `json:"failedSamples"`
	LastFailure         string               `json:"lastFailure,omitempty"`
	ConsecutiveFailures map[string]int       `json:"consecutiveFailures,omitempty"`
	FailureSince        map[string]time.Time `json:"failureSince,omitempty"`
	Unsaved             bool                 `json:"unsaved,omitempty"`
}

func RunBake(ctx context.Context, v BakeVerdict, probe func(context.Context) (map[string]string, error), observed func(BakeVerdict) error) (BakeVerdict, error) {
	v.Started = time.Now().UTC()
	v.Finished, v.HealthySince = time.Time{}, time.Time{}
	if v.FirstSample.IsZero() {
		v.FirstSample = v.Started
	}
	v.ConsecutiveFailures = map[string]int{}
	v.FailureSince = map[string]time.Time{}
	persist := func() error {
		if observed == nil {
			return nil
		}
		return observed(v)
	}
	fail := func(reason string) (BakeVerdict, error) {
		v.Reason, v.Finished = reason, time.Now().UTC()
		err := persist()
		v.Unsaved = err != nil
		return v, errors.Join(errors.New(reason), err)
	}
	if probe == nil {
		return fail("invalid bake observation")
	}
	if err := persist(); err != nil {
		return v, err
	}
	deadline := v.FirstSample.Add(MaxBakeWindow)
	total, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		if !time.Now().Before(deadline) {
			return fail("bake total observation bound exceeded")
		}
		if err := ctx.Err(); err != nil {
			return v, err
		}
		sample, stop := context.WithTimeout(total, sampleBudget)
		checks, failure := probe(sample)
		if sample.Err() != nil {
			failure = sample.Err()
			if checks == nil {
				checks = map[string]string{}
			}
			if len(checks) == 0 {
				checks["observation"] = failure.Error()
			}
		}
		stop()
		if !time.Now().Before(deadline) {
			return fail("bake total observation bound exceeded")
		}
		if err := ctx.Err(); err != nil {
			return v, err
		}
		v.Samples++
		v.Checks = maps.Clone(checks)
		if len(checks) == 0 {
			failure = errors.New("bake has no observations")
		}
		failed := map[string]int{}
		since := map[string]time.Time{}
		if failure != nil {
			v.FailedSamples++
			v.LastFailure = failure.Error()
			v.HealthySince = time.Time{}
			for key, value := range checks {
				if value != "ok" && !strings.HasPrefix(value, "served by ") && key != "terrabase-writer-waits" {
					failed[key] = v.ConsecutiveFailures[key] + 1
				}
			}
			if len(failed) == 0 {
				failed["observation"] = v.ConsecutiveFailures["observation"] + 1
			}
		} else if v.HealthySince.IsZero() {
			v.HealthySince = time.Now().UTC()
		}
		for key, count := range failed {
			since[key] = v.FailureSince[key]
			if count == 1 || since[key].IsZero() {
				since[key] = time.Now().UTC()
			}
		}
		v.ConsecutiveFailures, v.FailureSince = failed, since
		for key, count := range failed {
			if count >= 3 && time.Since(since[key]) >= BakeFailureDuration {
				return fail("bake probe " + key + " failed continuously for at least 15 seconds: " + v.LastFailure)
			}
		}
		if err := persist(); err != nil {
			return v, err
		}
		if failure == nil && time.Since(v.HealthySince) >= BakeWindow {
			v.Finished = time.Now().UTC()
			return v, persist()
		}
		select {
		case <-total.Done():
			if !time.Now().Before(deadline) {
				return fail("bake total observation bound exceeded")
			}
			return v, ctx.Err()
		case <-tick.C:
		}
	}
}
