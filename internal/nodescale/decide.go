package nodescale

import (
	"fmt"
	"slices"
	"time"
)

const (
	MinNodes      = 3
	MaxNodes      = 12
	Interval      = 30 * time.Second // how often the leader samples and decides
	SampleMaxAge  = 2 * time.Minute  // a node's load older than this is missing
	UpThreshold   = 0.75
	DownThreshold = 0.55
	UpWindow      = 5 * time.Minute
	DownWindow    = 30 * time.Minute
	UpCooldown    = 10 * time.Minute // after any change
	DownCooldown  = 30 * time.Minute // after any change
)

type Sample struct {
	At          time.Time
	Nodes       int // nodes the region had
	Reporting   int // nodes with a fresh load
	Utilization map[Signal]float64
}

func (s Sample) Complete() bool {
	return s.Utilization != nil && s.Reporting >= s.Nodes && s.Nodes > 0
}

// History keeps the samples Decide needs, oldest first.
type History struct{ samples []Sample }

// Add appends s unless it is not newer than the last sample, then drops samples Decide can no longer use.
func (h *History) Add(s Sample) {
	if n := len(h.samples); n > 0 && !s.At.After(h.samples[n-1].At) {
		return
	}
	h.samples = append(h.samples, s)
	cutoff := s.At.Add(-DownWindow - 2*Interval)
	h.samples = slices.DeleteFunc(h.samples, func(x Sample) bool { return x.At.Before(cutoff) })
}

// Samples returns a copy of the kept samples, oldest first.
func (h *History) Samples() []Sample { return slices.Clone(h.samples) }

type Action string

const (
	Hold Action = "hold"
	Up   Action = "up"
	Down Action = "down"
)

type State struct {
	Nodes      int       // nodes now (quorum + pool), as OCI shows them
	Allowance  int       // most nodes the budget allows; below Nodes counts as Nodes
	LastChange time.Time // last scale-up or scale-down start; zero = never
	Busy       bool      // a scale action or node operation is in flight
	Samples    []Sample  // History.Samples()
}

type Decision struct {
	Action    Action
	Nodes     int
	Want      int     // nodes the load wants, even when the action holds
	Saturated bool    // the load wants more at MaxNodes
	Pressure  float64 // highest utilization in the latest complete sample, 0 without one
	Signal    Signal  // the signal behind Pressure
	Reason    string  // one short sentence for the decision journal and dashboard
}

// Decide returns what the region should do at now. Rules are checked in order; the first that applies decides.
func Decide(state State, now time.Time) Decision {
	d := Decision{Action: Hold, Nodes: state.Nodes, Want: state.Nodes}
	hold := func(reason string) Decision {
		d.Reason = reason
		return d
	}
	samples := state.Samples
	if n := len(samples); n > 0 && samples[n-1].Complete() {
		d.Pressure, d.Signal = pressure(samples[n-1])
	}
	switch {
	case state.Busy:
		return hold("a scale action or node operation is running")
	case state.Nodes > MaxNodes:
		d.Action, d.Want = Down, MaxNodes
		d.Reason = fmt.Sprintf("above the maximum of %d nodes", MaxNodes)
		return d
	case state.Nodes < MinNodes:
		return hold(fmt.Sprintf("fewer than %d nodes: quorum repair belongs to controller membership", MinNodes))
	}
	if n := len(samples); n == 0 || now.Sub(samples[n-1].At) > 2*Interval || !samples[n-1].Complete() {
		return hold("missing load samples")
	}
	if up, ok := window(samples, state.Nodes, now, UpWindow); ok && every(up, hot) {
		d.Want = state.Nodes + 1
		allowed := max(state.Allowance, state.Nodes)
		left := cooldownLeft(state.LastChange, now, UpCooldown)
		switch {
		case state.Nodes >= MaxNodes:
			d.Saturated = true
			return hold(fmt.Sprintf("at the maximum of %d nodes", MaxNodes))
		case left > 0:
			return hold(cooldownReason(left))
		case state.Nodes+1 > allowed:
			return hold(fmt.Sprintf("the budget allows %d nodes", allowed))
		}
		d.Action = Up
		d.Reason = fmt.Sprintf("%s %.2f >= %.2f for %s", d.Signal, d.Pressure, UpThreshold, UpWindow)
		return d
	}
	if down, ok := window(samples, state.Nodes, now, DownWindow); ok && state.Nodes > MinNodes &&
		every(down, func(s Sample) bool { return quiet(s, state.Nodes) }) {
		d.Want = state.Nodes - 1
		if left := cooldownLeft(state.LastChange, now, DownCooldown); left > 0 {
			return hold(cooldownReason(left))
		}
		d.Action = Down
		d.Reason = fmt.Sprintf("every signal <= %.2f on %d nodes for %s", DownThreshold, state.Nodes-1, DownWindow)
		return d
	}
	return hold("load within band")
}

// window returns the samples of the last d when they cover it: all of them are complete at nodes, a complete
// sample at nodes starts no later than the window's start plus one Interval, and no gap up to now exceeds 2*Interval.
func window(samples []Sample, nodes int, now time.Time, d time.Duration) ([]Sample, bool) {
	n := len(samples)
	if n == 0 || now.Sub(samples[n-1].At) > 2*Interval {
		return nil, false
	}
	from := now.Add(-d)
	start := -1
	for i, s := range samples {
		if !s.At.After(from.Add(Interval)) && s.Complete() && s.Nodes == nodes {
			start = i
		}
	}
	if start < 0 {
		return nil, false
	}
	for i := start + 1; i < n; i++ {
		if samples[i].At.Sub(samples[i-1].At) > 2*Interval {
			return nil, false
		}
	}
	first := slices.IndexFunc(samples, func(s Sample) bool { return !s.At.Before(from) })
	if first < 0 {
		return nil, false
	}
	in := samples[first:]
	if !every(in, func(s Sample) bool { return s.Complete() && s.Nodes == nodes }) {
		return nil, false
	}
	return in, true
}

// every reports whether ok holds for each sample.
func every(samples []Sample, ok func(Sample) bool) bool {
	return !slices.ContainsFunc(samples, func(s Sample) bool { return !ok(s) })
}

// hot reports whether some signal is at or above the up threshold.
func hot(s Sample) bool {
	return slices.ContainsFunc(Signals, func(sig Signal) bool { return s.Utilization[sig] >= UpThreshold })
}

// quiet reports whether every signal, projected onto one node fewer, stays at or below the down threshold.
func quiet(s Sample, nodes int) bool {
	for _, sig := range Signals {
		if s.Utilization[sig]*float64(nodes)/float64(nodes-1) > DownThreshold {
			return false
		}
	}
	return true
}

// pressure returns the highest utilization of s and its signal; ties go to the earlier signal.
func pressure(s Sample) (float64, Signal) {
	var top Signal
	var highest float64
	for _, sig := range Signals {
		if u := s.Utilization[sig]; top == "" || u > highest {
			top, highest = sig, u
		}
	}
	return highest, top
}

// cooldownLeft is how much of a cooldown since last is still to run; a zero last means never changed.
func cooldownLeft(last, now time.Time, cooldown time.Duration) time.Duration {
	if last.IsZero() {
		return 0
	}
	return max(cooldown-now.Sub(last), 0)
}

func cooldownReason(left time.Duration) string {
	return fmt.Sprintf("cooldown after the last change, %s left", left.Round(time.Second))
}
