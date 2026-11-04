package decisionlog

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

type fakeArchive struct {
	decisions []Decision
	complete  bool
	scans     atomic.Int64
}

func (archive *fakeArchive) Scan(_ context.Context, since time.Time, maxScan int, visit func(Decision) bool) (bool, error) {
	archive.scans.Add(1)
	scanned := 0
	for _, decision := range archive.decisions {
		if decision.Time.Before(since) {
			continue
		}
		if scanned == maxScan {
			return false, nil
		}
		scanned++
		if !visit(decision) {
			return true, nil
		}
	}
	return archive.complete, nil
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestJournalQueryReadsArchiveBeyondWindow(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	archive := &fakeArchive{complete: true}
	for index := range 6 {
		archive.decisions = append(archive.decisions, Decision{ID: fmt.Sprintf("d%d", index), Region: "gru",
			Kind: KindHeld, Time: base.Add(time.Duration(index) * time.Minute)})
	}
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 2, Archive: archive})
	for _, decision := range archive.decisions {
		journal.Ingest(decision)
	}
	result, err := journal.Query(t.Context(), Query{Since: base})
	if err != nil || len(result.Decisions) != 6 || result.Partial {
		t.Fatalf("result = %+v, %v", result, err)
	}
	for index, decision := range result.Decisions {
		if decision.ID != fmt.Sprintf("d%d", 5-index) {
			t.Fatalf("order %d = %s", index, decision.ID)
		}
	}
}

func TestJournalChainAcrossArchive(t *testing.T) {
	base := time.Now().Add(-time.Hour).UTC()
	root := Decision{ID: newIDAt(base), Region: "gru", Kind: KindReleaseAdmitted, Time: base}
	canary := Decision{ID: newIDAt(base.Add(time.Minute)), Region: "gru", Kind: KindUpgradeStarted,
		ParentID: root.ID, Time: base.Add(time.Minute)}
	batch := Decision{ID: newIDAt(base.Add(2 * time.Minute)), Region: "gru", Kind: KindCanaryPromoted,
		ParentID: canary.ID, Time: base.Add(2 * time.Minute)}
	done := Decision{ID: newIDAt(base.Add(3 * time.Minute)), Region: "gru", Kind: KindRolloutCompleted,
		ParentID: batch.ID, Time: base.Add(3 * time.Minute)}
	archive := &fakeArchive{complete: true, decisions: []Decision{root, canary, batch, done}}
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 2, Archive: archive})
	for _, decision := range archive.decisions {
		journal.Ingest(decision)
	}
	chain, err := journal.Chain(t.Context(), done.ID)
	if err != nil {
		t.Fatal(err)
	}
	if chain.Root.ID != root.ID || len(chain.Decisions) != 4 || chain.Latest.ID != done.ID {
		t.Fatalf("chain = %+v", chain)
	}
	if _, err := journal.Chain(t.Context(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing chain err = %v", err)
	}
}
