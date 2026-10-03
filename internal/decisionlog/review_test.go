package decisionlog

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// These pin the fixes for the ts-reviewer findings on PR #121.

type failingArchive struct{}

func (failingArchive) Scan(context.Context, time.Time, int, func(Decision) bool) (bool, error) {
	return false, errors.New("jetstream: timeout")
}

func TestFullPageWithUnsearchedHistoryIsTruncated(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	archive := &fakeArchive{complete: true}
	for index := range 4 {
		archive.decisions = append(archive.decisions, Decision{ID: fmt.Sprintf("d%d", index), Region: "gru",
			Kind: KindHeld, Time: base.Add(time.Duration(index) * time.Minute)})
	}
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 2, Archive: archive})
	for _, decision := range archive.decisions {
		journal.Ingest(decision)
	}
	// Memory holds exactly the page; older matches are archived.
	result, err := journal.Query(t.Context(), Query{Limit: 2})
	if err != nil || len(result.Decisions) != 2 || !result.Truncated {
		t.Fatalf("a full page with archived history = %+v, %v", result, err)
	}
	// A range memory covers completely is exhaustive.
	recent, _ := journal.Query(t.Context(), Query{Limit: 2, Since: base.Add(3 * time.Minute)})
	if recent.Truncated || recent.Partial {
		t.Fatalf("a covered range = %+v", recent)
	}
}

func TestArchiveScanSkipsSkewedRecordsInsteadOfStopping(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	older := Decision{ID: "older", Region: "gru", Kind: KindHeld, Time: base.Add(time.Minute)}
	// Published first by a controller whose clock runs ahead.
	ahead := Decision{ID: "ahead", Region: "gru", Kind: KindHeld, Time: base.Add(4 * time.Minute)}
	newest := []Decision{{ID: "n1", Region: "gru", Kind: KindHeld, Time: base.Add(5 * time.Minute)},
		{ID: "n2", Region: "gru", Kind: KindHeld, Time: base.Add(6 * time.Minute)}}
	archive := &fakeArchive{complete: true, decisions: []Decision{ahead, older, newest[0], newest[1]}}
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 3, Archive: archive})
	journal.Ingest(ahead)
	for _, decision := range newest {
		journal.Ingest(decision)
	}
	journal.MarkCoveredFrom(base.Add(2 * time.Minute))
	result, _ := journal.Query(t.Context(), Query{Since: base})
	found := map[string]bool{}
	for _, decision := range result.Decisions {
		found[decision.ID] = true
	}
	if !found["older"] {
		t.Fatalf("an archived record behind a skewed one was skipped: %+v", result)
	}
}

func TestChainLookupFailuresAreNotNotFound(t *testing.T) {
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 2, Archive: failingArchive{}})
	missing := newIDAt(time.Now().Add(-time.Hour))
	if _, err := journal.Chain(t.Context(), missing); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an archive outage = %v, want ErrUnavailable", err)
	}
}

func TestChainFindsParentsOlderThanADay(t *testing.T) {
	now := time.Now().UTC()
	admission := Decision{ID: newIDAt(now.Add(-3 * 24 * time.Hour)), Region: "gru", Kind: KindReleaseAdmitted,
		Time: now.Add(-3 * 24 * time.Hour)}
	hold := Decision{ID: newIDAt(now.Add(-time.Hour)), Region: "gru", Kind: KindHeld, ParentID: admission.ID,
		Time: now.Add(-time.Hour)}
	archive := &fakeArchive{complete: true, decisions: []Decision{admission, hold}}
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 1, Archive: archive})
	journal.Ingest(admission)
	journal.Ingest(hold) // evicts the admission from memory
	chain, err := journal.Chain(t.Context(), hold.ID)
	if err != nil || chain.Root.ID != admission.ID || len(chain.Decisions) != 2 {
		t.Fatalf("chain = %+v, %v", chain, err)
	}
}

func TestQueriesDuringReplayArePartial(t *testing.T) {
	journal := NewJournal(JournalConfig{Region: "gru"})
	journal.beginReplay()
	if result, _ := journal.Query(t.Context(), Query{}); !result.Partial {
		t.Fatal("a query during the stream replay is reported complete")
	}
	journal.endReplay()
	if result, _ := journal.Query(t.Context(), Query{}); result.Partial {
		t.Fatal("a query after the replay is partial")
	}
}

func TestLongChainKeepsItsLatestDecision(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	decisions := []Decision{{ID: "root", Time: base}}
	for index := range MaxQueryLimit + 10 {
		decisions = append(decisions, Decision{ID: fmt.Sprintf("c%05d", index), ParentID: "root",
			Time: base.Add(time.Duration(index+1) * time.Second)})
	}
	last := decisions[len(decisions)-1]
	chain, ok := BuildChain(decisions, last.ID)
	if !ok || !chain.Truncated || chain.Latest.ID != last.ID || len(chain.Decisions) > MaxQueryLimit ||
		chain.Decisions[0].ID != "root" || chain.Decisions[len(chain.Decisions)-1].ID != last.ID {
		t.Fatalf("chain: truncated=%v latest=%s len=%d", chain.Truncated, chain.Latest.ID, len(chain.Decisions))
	}
	middle := decisions[5].ID
	if chain, _ := BuildChain(decisions, middle); !containsID(chain.Decisions, middle) {
		t.Fatal("a truncated chain dropped the requested decision")
	}
}

func containsID(decisions []Decision, id string) bool {
	for _, decision := range decisions {
		if decision.ID == id {
			return true
		}
	}
	return false
}
