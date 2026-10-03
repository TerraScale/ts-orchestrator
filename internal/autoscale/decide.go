package autoscale

import (
	"math"
	"slices"
	"time"
)

// Reading is one aggregated signal value for the current replica set.
// Samples below the signal's floor make the reading unavailable.
type Reading struct {
	Signal  SignalName
	Value   float64
	Samples int
}

// Recommendation is one clamped raw recommendation kept for stabilization.
type Recommendation struct {
	At       time.Time
	Replicas int
}

// History is the decision memory of one service. A caller that loses it, for
// example after an authority failover, should restart with Reset so that the
// cooldowns apply from that moment instead of permitting an immediate change.
type History struct {
	Recommendations []Recommendation
	LastScaleUp     time.Time
	LastScaleDown   time.Time
}

// Reset returns a conservative history that treats now as the last change in
// both directions.
func Reset(now time.Time) History {
	return History{LastScaleUp: now, LastScaleDown: now}
}

func (h History) lastChange() time.Time {
	if h.LastScaleUp.After(h.LastScaleDown) {
		return h.LastScaleUp
	}
	return h.LastScaleDown
}

// Input is the observed state used by one decision.
type Input struct {
	Current  int
	Bounds   Bounds
	Readings []Reading
	Now      time.Time
}

// Reason values explain every decision, including holds.
const (
	ReasonBelowMin             = "below-min"
	ReasonAboveMax             = "above-max"
	ReasonScaledToZero         = "scaled-to-zero"
	ReasonNoSignalData         = "no-signal-data"
	ReasonWithinTolerance      = "within-tolerance"
	ReasonScaleUp              = "scale-up"
	ReasonScaleDown            = "scale-down"
	ReasonScaleUpStabilizing   = "scale-up-stabilizing"
	ReasonScaleDownStabilizing = "scale-down-stabilizing"
	ReasonScaleUpCooldown      = "scale-up-cooldown"
	ReasonScaleDownCooldown    = "scale-down-cooldown"
	ReasonScaleDownSignalGap   = "scale-down-blocked-missing-signal"
	ReasonAtBound              = "at-bound"
)

// Decision is the outcome of one evaluation. To equals From for every hold.
// History must be passed to the next evaluation of the same service.
type Decision struct {
	From        int
	To          int
	Recommended int
	Reason      string
	History     History
}

// Changed reports whether the decision asks for a different replica count.
func (d Decision) Changed() bool { return d.To != d.From }

// Decide is deterministic for equal inputs. Bounds violations are corrected
// immediately; otherwise every change must pass the tolerance band, the
// stabilization window of its direction, its cooldown and its step limit.
// The policy and bounds must already be valid.
func Decide(policy Policy, in Input, history History) Decision {
	history = History{
		Recommendations: slices.Clone(history.Recommendations),
		LastScaleUp:     history.LastScaleUp,
		LastScaleDown:   history.LastScaleDown,
	}
	decision := Decision{From: in.Current, To: in.Current, Recommended: in.Current}
	finish := func(to int, reason string) Decision {
		decision.To = to
		decision.Reason = reason
		if to > in.Current {
			history.LastScaleUp = in.Now
		} else if to < in.Current {
			history.LastScaleDown = in.Now
		}
		decision.History = history
		return decision
	}
	if in.Current < in.Bounds.Min {
		decision.Recommended = in.Bounds.Min
		return finish(in.Bounds.Min, ReasonBelowMin)
	}
	if in.Current > in.Bounds.Max {
		decision.Recommended = in.Bounds.Max
		return finish(in.Bounds.Max, ReasonAboveMax)
	}
	if in.Current == 0 {
		// Per-replica signals are undefined without replicas; only the lower
		// bound can bring a service back from zero.
		return finish(0, ReasonScaledToZero)
	}

	want, available, allAvailable := 0, 0, true
	for _, signal := range policy.Signals {
		reading, ok := findReading(in.Readings, signal)
		if !ok {
			allAvailable = false
			continue
		}
		available++
		want = max(want, signalRecommendation(in.Current, reading.Value/signal.Target, policy.Tolerance))
	}
	if available == 0 {
		return finish(in.Current, ReasonNoSignalData)
	}
	raw := in.Bounds.clamp(want)
	gapBlocked := false
	if raw < in.Current && !allAvailable {
		raw, gapBlocked = in.Current, true
	}
	decision.Recommended = raw
	history.Recommendations = append(pruneRecommendations(history.Recommendations, in.Now, policy),
		Recommendation{At: in.Now, Replicas: raw})

	switch {
	case gapBlocked:
		return finish(in.Current, ReasonScaleDownSignalGap)
	case raw == in.Current && want != in.Current:
		return finish(in.Current, ReasonAtBound)
	case raw == in.Current:
		return finish(in.Current, ReasonWithinTolerance)
	case raw > in.Current:
		// The smallest recommendation inside the window must still exceed the
		// current count, so one transient spike cannot add capacity.
		stabilized := windowExtreme(history.Recommendations, in.Now, policy.upStabilization(), false)
		if stabilized <= in.Current || !windowCovered(history.Recommendations, in.Now, policy.upStabilization()) {
			return finish(in.Current, ReasonScaleUpStabilizing)
		}
		if within(in.Now, history.LastScaleUp, policy.upCooldown()) {
			return finish(in.Current, ReasonScaleUpCooldown)
		}
		to := stabilized
		if policy.MaxStepUp > 0 {
			to = min(to, in.Current+policy.MaxStepUp)
		}
		return finish(to, ReasonScaleUp)
	default:
		// The largest recommendation inside the window must still be below the
		// current count, so one quiet sample cannot remove capacity.
		stabilized := windowExtreme(history.Recommendations, in.Now, policy.downStabilization(), true)
		if stabilized >= in.Current || !windowCovered(history.Recommendations, in.Now, policy.downStabilization()) {
			return finish(in.Current, ReasonScaleDownStabilizing)
		}
		if within(in.Now, history.lastChange(), policy.downCooldown()) {
			return finish(in.Current, ReasonScaleDownCooldown)
		}
		to := stabilized
		if policy.MaxStepDown > 0 {
			to = max(to, in.Current-policy.MaxStepDown)
		}
		// Per-replica signals are undefined at zero replicas, so no signal
		// could ever bring the service back: signals never scale to zero.
		// Only Bounds.Min (an operator decision) governs zero.
		to = max(to, 1)
		if to >= in.Current {
			return finish(in.Current, ReasonAtBound)
		}
		return finish(to, ReasonScaleDown)
	}
}

func findReading(readings []Reading, signal Signal) (Reading, bool) {
	for _, reading := range readings {
		if reading.Signal != signal.Name {
			continue
		}
		if reading.Samples < signal.minSamples() || math.IsNaN(reading.Value) || math.IsInf(reading.Value, 0) ||
			reading.Value < 0 {
			return Reading{}, false
		}
		return reading, true
	}
	return Reading{}, false
}

// signalRecommendation scales the current count by the load ratio unless the
// ratio is inside the tolerance band.
func signalRecommendation(current int, ratio, tolerance float64) int {
	if math.Abs(ratio-1) <= tolerance {
		return current
	}
	scaled := math.Ceil(float64(current) * ratio)
	if scaled > MaxReplicas {
		return MaxReplicas
	}
	return int(scaled)
}

// pruneRecommendations keeps every recommendation inside the longest window
// plus the newest one older than it, the boundary observation windowCovered
// needs: without it a window evaluated at an interval that does not divide it
// would never be covered.
func pruneRecommendations(recommendations []Recommendation, now time.Time, policy Policy) []Recommendation {
	keep := max(policy.upStabilization(), policy.downStabilization())
	boundary := -1
	for index, recommendation := range recommendations {
		age := now.Sub(recommendation.At)
		if age > keep && age <= 2*keep && (boundary < 0 || recommendation.At.After(recommendations[boundary].At)) {
			boundary = index
		}
	}
	kept := recommendations[:0:0]
	for index, recommendation := range recommendations {
		if recommendation.At.After(now) || now.Sub(recommendation.At) > keep && index != boundary {
			continue
		}
		kept = append(kept, recommendation)
	}
	return kept
}

func windowExtreme(recommendations []Recommendation, now time.Time, window time.Duration, largest bool) int {
	result, found := 0, false
	for _, recommendation := range recommendations {
		if now.Sub(recommendation.At) > window {
			continue
		}
		if !found || largest && recommendation.Replicas > result || !largest && recommendation.Replicas < result {
			result, found = recommendation.Replicas, true
		}
	}
	return result
}

// windowCovered requires an observation at least one full window old, so a
// fresh or restarted history cannot act on its first recommendation. The
// observation must also be at most two windows old: after a longer gap the
// window holds too few recent observations to stand for sustained load.
func windowCovered(recommendations []Recommendation, now time.Time, window time.Duration) bool {
	if window <= 0 {
		return true
	}
	for _, recommendation := range recommendations {
		if age := now.Sub(recommendation.At); age >= window && age <= 2*window {
			return true
		}
	}
	return false
}

func within(now, since time.Time, duration time.Duration) bool {
	return duration > 0 && !since.IsZero() && now.Sub(since) < duration
}
