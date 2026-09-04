// SLO burn-rate evaluation for the D-75 monthly API availability target.
//
// The workspace goal (D-67/D-75) fixes two rules: the orchestrator pages
// only on SLO burn-rate, and the published target is 99.9% monthly API
// availability per Region measured by the external probe. This file computes
// burn rates from error ratios and decides when an evaluation pages. It
// never emits a page itself: it returns an SLOBurnRatePageEvent the caller
// routes through EventRouter.EmitPage, which re-validates the name prefix,
// window, burn bounds, and label allow-list before the event can reach the
// page sink.
//
// The thresholds follow the Google SRE multiwindow pattern for a 99.9%
// 30-day SLO: a fast burn of 14.4 consumes 2% of the error budget in one
// hour (long window 1h confirmed by short window 5m) and a slow burn of 6
// consumes 5% in six hours (long window 6h confirmed by short window 30m).
// Both windows of a tier must be above threshold before that tier pages, so
// a single short spike cannot page on its own. Anything below both tiers is
// dashboard-only: the caller may record the burn through
// SLOBurnDashboardObservation and must not page.
package observability

import (
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	// SLOAPIAvailabilityTarget is the D-75 target: 99.9% monthly API
	// availability per Region.
	SLOAPIAvailabilityTarget = 0.999

	// SLOAPIBurnMetric is the only page-event name this package evaluates.
	// The EventRouter enforces the slo.burn_rate. prefix independently.
	SLOAPIBurnMetric = "slo.burn_rate.api"

	// FastBurnThreshold pages when both the 1h and 5m burn rates exceed it.
	FastBurnThreshold = 14.4
	// FastBurnLongWindow is the fast-burn confirmation window.
	FastBurnLongWindow = "1h"
	// FastBurnShortWindow is the fast-burn reset window.
	FastBurnShortWindow = "5m"

	// SlowBurnThreshold pages when both the 6h and 30m burn rates exceed it.
	SlowBurnThreshold = 6.0
	// SlowBurnLongWindow is the slow-burn confirmation window.
	SlowBurnLongWindow = "6h"
	// SlowBurnShortWindow is the slow-burn reset window.
	SlowBurnShortWindow = "30m"
)

// SLOSpec is the evaluated availability target. Target is the required
// success ratio in (0, 1); the D-75 API target is SLOAPIAvailabilityTarget.
type SLOSpec struct {
	Target float64
}

func (s SLOSpec) validate() error {
	if math.IsNaN(s.Target) || math.IsInf(s.Target, 0) {
		return errors.New("SLO target must be finite")
	}
	if s.Target <= 0 || s.Target >= 1 {
		return errors.New("SLO target must be between 0 and 1 exclusive")
	}
	return nil
}

// BurnRate converts an error ratio into a multiple of the error budget:
// errorRatio / (1 - target). A ratio of 0 burns nothing; a ratio equal to
// the budget burns at 1x.
func BurnRate(errorRatio float64, spec SLOSpec) (float64, error) {
	if err := spec.validate(); err != nil {
		return 0, err
	}
	if math.IsNaN(errorRatio) || math.IsInf(errorRatio, 0) {
		return 0, errors.New("error ratio must be finite")
	}
	if errorRatio < 0 || errorRatio > 1 {
		return 0, errors.New("error ratio must be between 0 and 1")
	}
	return errorRatio / (1 - spec.Target), nil
}

// SLOBurnWindows carries the four multiwindow burn rates of one evaluation:
// the fast tier (1h long, 5m short) and the slow tier (6h long, 30m short).
type SLOBurnWindows struct {
	FastLong  float64
	FastShort float64
	SlowLong  float64
	SlowShort float64
}

func (w SLOBurnWindows) validate() error {
	for name, rate := range map[string]float64{
		"fast-long": w.FastLong, "fast-short": w.FastShort,
		"slow-long": w.SlowLong, "slow-short": w.SlowShort,
	} {
		if math.IsNaN(rate) || math.IsInf(rate, 0) {
			return fmt.Errorf("SLO %s burn rate must be finite", name)
		}
		if rate < 0 || rate > 1_000_000 {
			return fmt.Errorf("SLO %s burn rate must be between 0 and 1000000", name)
		}
	}
	return nil
}

// EvaluateSLOBurn decides whether one multiwindow evaluation pages. It
// returns nil with no error when neither tier is burning: below-threshold
// burn is dashboard-only and must never reach the page sink. The fast tier
// wins when both tiers are burning. The returned event always carries the
// canonical SLOAPIBurnMetric name and a fixed window the EventRouter admits.
func EvaluateSLOBurn(allow LabelAllowList, labels map[string]string, windows SLOBurnWindows, timestamp time.Time) (*SLOBurnRatePageEvent, error) {
	if err := allow.Validate(); err != nil {
		return nil, err
	}
	if err := windows.validate(); err != nil {
		return nil, err
	}
	if err := allow.ValidateLabels(labels); err != nil {
		return nil, err
	}
	fast := windows.FastLong >= FastBurnThreshold && windows.FastShort >= FastBurnThreshold
	slow := windows.SlowLong >= SlowBurnThreshold && windows.SlowShort >= SlowBurnThreshold
	switch {
	case fast:
		event := SLOBurnRatePageEvent{
			Name:      SLOAPIBurnMetric,
			Labels:    cloneLabels(labels),
			BurnRate:  windows.FastLong,
			Window:    FastBurnLongWindow,
			Timestamp: timestamp,
		}
		return &event, nil
	case slow:
		event := SLOBurnRatePageEvent{
			Name:      SLOAPIBurnMetric,
			Labels:    cloneLabels(labels),
			BurnRate:  windows.SlowLong,
			Window:    SlowBurnLongWindow,
			Timestamp: timestamp,
		}
		return &event, nil
	default:
		return nil, nil
	}
}

// SLOBurnDashboardObservation records one burn rate as a dashboard-only
// fact. It is the non-paging path for below-threshold burn: the returned
// observation can only reach the dashboard sink through
// EventRouter.EmitObservation and can never page, even though it shares the
// SLO burn metric name.
func SLOBurnDashboardObservation(allow LabelAllowList, labels map[string]string, burnRate float64, timestamp time.Time) (DashboardObservation, error) {
	if math.IsNaN(burnRate) || math.IsInf(burnRate, 0) {
		return DashboardObservation{}, errors.New("SLO burn rate must be finite")
	}
	if burnRate < 0 || burnRate > 1_000_000 {
		return DashboardObservation{}, errors.New("SLO burn rate must be between 0 and 1000000")
	}
	if err := allow.Validate(); err != nil {
		return DashboardObservation{}, err
	}
	if err := allow.ValidateLabels(labels); err != nil {
		return DashboardObservation{}, err
	}
	return DashboardObservation{
		Name:      SLOAPIBurnMetric,
		Labels:    cloneLabels(labels),
		Value:     burnRate,
		Timestamp: timestamp,
	}, nil
}
