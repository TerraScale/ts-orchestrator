package regionplanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

type fakeJournal struct {
	byRegion map[string][]decisionlog.Decision
	queries  []decisionlog.Query
}

func (journal *fakeJournal) Query(_ context.Context, query decisionlog.Query) (decisionlog.Result, error) {
	journal.queries = append(journal.queries, query)
	if len(query.Regions) != 1 {
		return decisionlog.Result{}, errors.New("one region per query")
	}
	if query.Limit == 0 {
		return decisionlog.Result{Decisions: journal.byRegion[query.Regions[0]]}, nil
	}
	// Window, newest first, Limit and Truncated like the journal.
	var matched []decisionlog.Decision
	for _, decision := range journal.byRegion[query.Regions[0]] {
		if !decision.Time.Before(query.Since) && decision.Time.Before(query.Until) {
			matched = append(matched, decision)
		}
	}
	decisionlog.SortNewestFirst(matched)
	result := decisionlog.Result{Decisions: matched}
	if len(matched) > query.Limit {
		result.Decisions, result.Truncated = matched[:query.Limit], true
	}
	return result, nil
}

// TestPeerHoldsPageBackPastOtherHolds pins ts-reviewer 13199: other holds
// newer than the capacity evidence must not crowd it out of the window.
func TestPeerHoldsPageBackPastOtherHolds(t *testing.T) {
	t.Parallel()
	var decisions []decisionlog.Decision
	for index := range 3 {
		decisions = append(decisions, hold("cap-"+string(rune('a'+index)), "sfo", "out of host capacity",
			now.Add(-20*time.Hour-time.Duration(index)*time.Minute)))
	}
	for index := range 600 {
		decisions = append(decisions, hold("other-"+time.Duration(index).String(), "sfo", "waiting for an artifact",
			now.Add(-time.Duration(index)*time.Second)))
	}
	journal := &fakeJournal{byRegion: map[string][]decisionlog.Decision{"sfo": decisions}}
	source := PeerHolds{Decisions: func() decisionlog.Source { return journal }, Peers: []string{"sfo"},
		Now: func() time.Time { return now }}
	signals, err := source.Signals(t.Context(), now.Add(-24*time.Hour))
	if err != nil || len(signals) != 3 {
		t.Fatalf("signals = %d, %v (queries %d)", len(signals), err, len(journal.queries))
	}
	if len(journal.queries) < 3 || len(journal.queries) > maxPeerHoldPages {
		t.Fatalf("pages = %d", len(journal.queries))
	}
}

func (*fakeJournal) Chain(context.Context, string) (decisionlog.Chain, error) {
	return decisionlog.Chain{}, nil
}

func hold(id, region, reason string, at time.Time) decisionlog.Decision {
	return decisionlog.Decision{ID: id, Region: region, Time: at, Actor: decisionlog.Actor{Slice: "placement"},
		Kind: decisionlog.KindHeld, Reason: reason}
}

func TestPeerHoldsReadEachPeersCapacityHolds(t *testing.T) {
	t.Parallel()
	other := hold("g", "sfo", "out of host capacity", now.Add(-time.Hour))
	other.Actor.Slice = "rollout"
	journal := &fakeJournal{byRegion: map[string][]decisionlog.Decision{
		"sfo": {
			hold("a", "sfo", "OCI LaunchInstance: Out of host capacity", now.Add(-time.Hour)),
			hold("b", "sfo", "LimitExceeded: core count", now.Add(-2*time.Hour)),
			hold("c", "sfo", "waiting for an admitted artifact", now.Add(-time.Hour)),
			// A peer cannot raise signals for another region, outside the
			// window, or from another slice.
			hold("d", "fra", "out of host capacity", now.Add(-time.Hour)),
			hold("e", "sfo", "out of host capacity", now.Add(-48*time.Hour)),
			hold("f", "sfo", "out of host capacity", now.Add(time.Hour)),
			other,
		},
	}}
	source := PeerHolds{Decisions: func() decisionlog.Source { return journal }, Peers: []string{"SFO", "fra"},
		Now: func() time.Time { return now }}
	signals, err := source.Signals(t.Context(), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 2 || signals[0].Kind != SignalCapacityError || signals[1].Kind != SignalLimitError ||
		signals[0].Cell != "sfo" || signals[0].EvidenceDigest == signals[1].EvidenceDigest ||
		!digestToken.MatchString(signals[0].EvidenceDigest) {
		t.Fatalf("signals = %+v", signals)
	}
	if len(journal.queries) != 2 || journal.queries[0].Kinds[0] != decisionlog.KindHeld ||
		journal.queries[0].Actors[0] != "placement" {
		t.Fatalf("queries = %+v", journal.queries)
	}
	detached := PeerHolds{Decisions: func() decisionlog.Source { return nil }, Peers: []string{"sfo"}}
	if signals, err := detached.Signals(t.Context(), now); err != nil || signals != nil {
		t.Fatalf("detached journal = %v, %v", signals, err)
	}
}

type failingSource struct{}

func (failingSource) Signals(context.Context, time.Time) ([]Signal, error) {
	return nil, errors.New("unavailable")
}

func TestSourcesMergeAndReportFailures(t *testing.T) {
	t.Parallel()
	one := staticSource{signal(SignalLatency, "fra", "l1", time.Hour)}
	signals, err := Sources{one, nil, one}.Signals(t.Context(), now)
	if err != nil || len(signals) != 2 {
		t.Fatalf("merged = %v, %v", signals, err)
	}
	if _, err := (Sources{one, failingSource{}}).Signals(t.Context(), now); err == nil {
		t.Fatal("a failing source was hidden")
	}
	if ClassifyHold("Out Of Host Capacity") != SignalCapacityError || ClassifyHold("service limit reached") != SignalLimitError ||
		ClassifyHold("timeout") != "" {
		t.Fatal("hold classification changed")
	}
}
