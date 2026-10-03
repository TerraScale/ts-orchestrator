// Package insights computes the dashboard's ranked "needs attention" list
// and its plain-language summaries.
//
// An Engine evaluates a fixed set of rules over read-only inputs: the
// cell-wide observability snapshot, the metric history, the decision
// journal and a set of optional providers for data owned by slices that are
// still being built (rollouts, volumes, certificates, NetBird peers,
// autoscalers, budgets, cross-region reachability). A rule whose provider is
// not attached stays silent; it never invents data.
//
// Every insight explains why it fired, carries its evidence (the observed
// value and the threshold it crossed), links to the affected entity and
// suggests an action or CLI command. Insights are keyed by rule and entity,
// so one problem stays one insight while it lasts; the engine reports when
// insights open, escalate and resolve so the dashboard can raise a toast.
//
// Nothing here mutates control-plane state or feeds a decision back into
// the control plane.
package insights

import (
	"cmp"
	"slices"
	"time"
)

// Severity orders insights. Critical problems threaten availability or
// data; warnings need attention soon; info is worth knowing.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

// Rank returns a sortable weight, highest first.
func (severity Severity) Rank() int {
	switch severity {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Entity is what an insight is about.
type Entity struct {
	// Kind is region, member, host, volume, database, seat, rollout,
	// stream, consumer, operation, certificate, peer, autoscaler or budget.
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Region string `json:"region,omitempty"`
	// Href is the dashboard path that shows the entity.
	Href string `json:"href,omitempty"`
}

// Evidence is one observed value and the threshold it was compared with.
type Evidence struct {
	// Label is a short human name; Metric names the history series when
	// there is one, so the UI can chart it.
	Label      string            `json:"label"`
	Metric     string            `json:"metric,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Value      float64           `json:"value"`
	Text       string            `json:"text,omitempty"`
	Unit       string            `json:"unit,omitempty"`
	Comparison string            `json:"comparison,omitempty"`
	Threshold  *float64          `json:"threshold,omitempty"`
}

// Action is a suggested next step.
type Action struct {
	Label string `json:"label"`
	// Command is a CLI command line; Href is a dashboard path.
	Command string `json:"command,omitempty"`
	Href    string `json:"href,omitempty"`
}

// Insight is one open problem.
type Insight struct {
	// Key identifies the problem across evaluations: rule plus entity.
	Key      string   `json:"key"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	// Score orders insights of the same severity; larger is worse.
	Score    float64    `json:"score"`
	Region   string     `json:"region"`
	Title    string     `json:"title"`
	Why      string     `json:"why"`
	Evidence []Evidence `json:"evidence,omitempty"`
	Entity   Entity     `json:"entity"`
	Actions  []Action   `json:"actions,omitempty"`
	// FirstSeen is when the problem was first observed open; LastSeen is
	// the latest evaluation that still found it.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// inputs, when set, names exactly the inputs this insight was derived
	// from; it overrides its rule's inputs for the resolution guard, so a
	// rule with several independent branches resolves a branch that was
	// observed healthy even while another branch's input is unavailable.
	inputs []string
}

// Rank sorts insights worst first: severity, then score, then age, then key.
func Rank(insights []Insight) {
	slices.SortStableFunc(insights, func(left, right Insight) int {
		if order := cmp.Compare(right.Severity.Rank(), left.Severity.Rank()); order != 0 {
			return order
		}
		if order := cmp.Compare(right.Score, left.Score); order != 0 {
			return order
		}
		if order := left.FirstSeen.Compare(right.FirstSeen); order != 0 {
			return order
		}
		return cmp.Compare(left.Key, right.Key)
	})
}

// ChangeType is what happened to an insight.
type ChangeType string

const (
	ChangeOpened    ChangeType = "opened"
	ChangeEscalated ChangeType = "escalated"
	ChangeResolved  ChangeType = "resolved"
)

// Change is one transition, streamed to the dashboard for toasts and kept
// for summaries.
type Change struct {
	Type    ChangeType `json:"type"`
	Time    time.Time  `json:"time"`
	Insight Insight    `json:"insight"`
}

// Counts tallies insights by severity.
type Counts struct {
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
}

// Total returns every counted insight.
func (counts Counts) Total() int { return counts.Critical + counts.Warning + counts.Info }

// Count tallies insights by severity.
func Count(insights []Insight) Counts {
	var counts Counts
	for _, insight := range insights {
		switch insight.Severity {
		case SeverityCritical:
			counts.Critical++
		case SeverityWarning:
			counts.Warning++
		default:
			counts.Info++
		}
	}
	return counts
}
