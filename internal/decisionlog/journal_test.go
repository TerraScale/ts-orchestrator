package decisionlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSink struct {
	mu        sync.Mutex
	stored    []Decision
	failures  int
	block     chan struct{}
	attempted atomic.Int64
}

func (sink *fakeSink) Publish(ctx context.Context, decision Decision) error {
	sink.attempted.Add(1)
	if sink.block != nil {
		select {
		case <-sink.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.failures > 0 {
		sink.failures--
		return errors.New("unavailable")
	}
	sink.stored = append(sink.stored, decision)
	return nil
}

func (sink *fakeSink) count() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return len(sink.stored)
}

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

func TestJournalRecordFillsIdentityAndIndexes(t *testing.T) {
	journal := NewJournal(JournalConfig{Region: "GRU", Member: "ctrl-1"})
	id := journal.Record(t.Context(), Decision{Kind: KindHeld, Actor: Actor{Slice: "placement"},
		Subject: Subject{Kind: "member", ID: "m1"}, Summary: "member m1 held"})
	if id == "" {
		t.Fatal("empty ID")
	}
	result, err := journal.Query(t.Context(), Query{})
	if err != nil || len(result.Decisions) != 1 {
		t.Fatalf("result = %+v, %v", result, err)
	}
	decision := result.Decisions[0]
	if decision.Region != "gru" || decision.Actor.Member != "ctrl-1" || decision.Status != StatusSucceeded ||
		decision.Version != Version || decision.ID != id {
		t.Fatalf("decision = %+v", decision)
	}
	if result.Partial {
		t.Fatal("a journal that never evicted must be complete")
	}
}

func TestJournalRecordNeverBlocksAndCountsDrops(t *testing.T) {
	sink := &fakeSink{block: make(chan struct{})}
	journal := NewJournal(JournalConfig{Region: "gru", QueueSize: 2, Sink: sink})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { _ = journal.Run(ctx); close(done) }()
	finished := make(chan struct{})
	go func() {
		for index := range 50 {
			journal.Record(t.Context(), Decision{Kind: KindHeld, Summary: fmt.Sprint(index)})
		}
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked behind a stuck sink")
	}
	stats := journal.Stats()
	if stats.Recorded != 50 || stats.DroppedQueue == 0 || stats.Indexed != 50 {
		t.Fatalf("stats = %+v", stats)
	}
	close(sink.block)
	waitFor(t, func() bool { return journal.Stats().Queued == 0 })
	cancel()
	<-done
}

func TestJournalRunRetriesThenDrops(t *testing.T) {
	sink := &fakeSink{failures: 2}
	journal := NewJournal(JournalConfig{Region: "gru", Sink: sink})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = journal.Run(ctx) }()
	journal.Record(t.Context(), Decision{Kind: KindHeld})
	waitFor(t, func() bool { return sink.count() == 1 })
	if stats := journal.Stats(); stats.Published != 1 || stats.PublishFailed != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	sink.mu.Lock()
	sink.failures = publishAttempts
	sink.mu.Unlock()
	journal.Record(t.Context(), Decision{Kind: KindHeld})
	waitFor(t, func() bool { return journal.Stats().PublishFailed == 1 })
}

func TestJournalWaitsForLateSink(t *testing.T) {
	journal := NewJournal(JournalConfig{Region: "gru"})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = journal.Run(ctx) }()
	journal.Record(t.Context(), Decision{Kind: KindLeaderChanged})
	time.Sleep(50 * time.Millisecond)
	sink := &fakeSink{}
	journal.Attach(sink, nil)
	waitFor(t, func() bool { return sink.count() == 1 })
}

func TestJournalIngestDeduplicatesAndNotifies(t *testing.T) {
	journal := NewJournal(JournalConfig{Region: "gru"})
	ctx, cancel := context.WithCancel(t.Context())
	live := journal.Subscribe(ctx, 4)
	decision := Decision{ID: NewID(), Region: "gru", Kind: KindScaleUp}.Normalize(time.Now())
	if !journal.Ingest(decision) || journal.Ingest(decision) {
		t.Fatal("ingest must accept once")
	}
	select {
	case got := <-live:
		if got.ID != decision.ID {
			t.Fatalf("got %s", got.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber not notified")
	}
	cancel()
	waitFor(t, func() bool {
		_, open := <-live
		return !open
	})
}

func TestJournalEvictionMarksPartialWithoutArchive(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 3})
	for index := range 5 {
		journal.Ingest(Decision{ID: fmt.Sprintf("d%d", index), Region: "gru", Kind: KindHeld,
			Time: base.Add(time.Duration(index) * time.Minute)})
	}
	result, _ := journal.Query(t.Context(), Query{})
	if len(result.Decisions) != 3 || result.Decisions[0].ID != "d4" || !result.Partial {
		t.Fatalf("result = %+v", result)
	}
	// A range inside the window is complete.
	result, _ = journal.Query(t.Context(), Query{Since: base.Add(3 * time.Minute)})
	if result.Partial || len(result.Decisions) != 2 {
		t.Fatalf("windowed result = %+v", result)
	}
	// A full page from memory does not need the archive.
	result, _ = journal.Query(t.Context(), Query{Limit: 2})
	if result.Partial || !result.Truncated {
		t.Fatalf("page result = %+v", result)
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

func TestJournalQueryArchiveReturnsNewestBeyondScanBound(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	total := maxArchiveScan + maxArchiveScan/2
	archive := &fakeArchive{complete: true}
	for index := range total {
		archive.decisions = append(archive.decisions, Decision{ID: fmt.Sprintf("d%05d", index), Region: "gru",
			Kind: KindHeld, Time: base.Add(time.Duration(index) * time.Minute)})
	}
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 2, Archive: archive})
	for _, decision := range archive.decisions[total-4:] {
		journal.Ingest(decision)
	}
	// Memory holds the two newest; the page continues with the newest
	// archived decisions, not the oldest a single forward scan would read.
	result, err := journal.Query(t.Context(), Query{Limit: 10})
	if err != nil || len(result.Decisions) != 10 || result.Partial {
		t.Fatalf("result = %d decisions, partial %v, %v", len(result.Decisions), result.Partial, err)
	}
	for index, decision := range result.Decisions {
		if want := fmt.Sprintf("d%05d", total-1-index); decision.ID != want {
			t.Fatalf("order %d = %s, want %s", index, decision.ID, want)
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

func TestJournalConcurrentRecordQuerySubscribe(t *testing.T) {
	sink := &fakeSink{}
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 128, QueueSize: 64, Sink: sink})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = journal.Run(ctx) }()
	var group sync.WaitGroup
	for worker := range 8 {
		group.Go(func() {
			for index := range 200 {
				journal.Record(ctx, Decision{Kind: KindStageChanged, Actor: Actor{Slice: fmt.Sprint("w", worker)},
					Subject: Subject{Kind: "member", ID: fmt.Sprint(index)}})
			}
		})
		group.Go(func() {
			for range 50 {
				_, _ = journal.Query(ctx, Query{Actors: []string{fmt.Sprint("w", worker)}, Limit: 10})
				_ = journal.Stats()
			}
		})
		group.Go(func() {
			subCtx, subCancel := context.WithTimeout(ctx, 20*time.Millisecond)
			defer subCancel()
			for range journal.Subscribe(subCtx, 8) {
			}
		})
	}
	group.Wait()
	if stats := journal.Stats(); stats.Recorded != 1600 || stats.Indexed != 128 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestDefaultRecorderFallsBackToLog(t *testing.T) {
	var buffer bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buffer, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	id := Record(t.Context(), Decision{Kind: KindPeerEnrolled, Actor: Actor{Slice: "netbird"},
		Summary: "peer enrolled"})
	if id == "" || !strings.Contains(buffer.String(), "peer enrolled") ||
		!strings.Contains(buffer.String(), "kind=peer_enrolled") {
		t.Fatalf("log = %q", buffer.String())
	}
	journal := NewJournal(JournalConfig{Region: "gru"})
	restore := SetDefault(journal)
	Record(t.Context(), Decision{Kind: KindScaleUp})
	if journal.Stats().Recorded != 1 {
		t.Fatal("installed journal did not record")
	}
	restore()
	if Default() != nil {
		t.Fatal("restore did not remove the journal")
	}
}

func TestNormalizeBoundsRecord(t *testing.T) {
	long := strings.Repeat("é", 2000)
	decision := Decision{Summary: long, Reason: long, Subject: Subject{ID: long}}
	for index := range 40 {
		decision.Signals = append(decision.Signals, Signal{Name: fmt.Sprint(index), Text: long})
		decision.Related = append(decision.Related, fmt.Sprint(index))
		decision.Alternatives = append(decision.Alternatives, Alternative{Option: long, Reason: long})
	}
	decision.Attrs = map[string]string{}
	for index := range 40 {
		decision.Attrs[fmt.Sprint("k", index)] = long
	}
	normalized := decision.Normalize(time.Now())
	if len(normalized.Signals) != maxSignals || len(normalized.Related) != maxRelated ||
		len(normalized.Alternatives) != maxAlternatives || len(normalized.Attrs) != maxAttrs {
		t.Fatalf("bounds not applied")
	}
	if len(normalized.Summary) > maxSummaryBytes || !strings.HasPrefix(long, normalized.Summary) {
		t.Fatalf("summary not clipped on a rune boundary")
	}
	if normalized.ID == "" || normalized.Version != Version || normalized.Status != StatusSucceeded {
		t.Fatalf("defaults = %+v", normalized)
	}
	stamped, ok := IDTime(normalized.ID)
	if !ok || stamped.Sub(normalized.Time).Abs() > time.Millisecond {
		t.Fatalf("ID time = %v %v", stamped, normalized.Time)
	}
}
