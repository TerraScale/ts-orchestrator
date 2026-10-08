package decisionlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	older := Decision{ID: "00000000007M2BHZ0MP819C5RF", Region: "gru", Kind: KindHeld, Time: base.Add(time.Minute)}
	// Published first by a controller whose clock runs ahead.
	ahead := Decision{ID: "0000000000HPQQ4SQ462GH8ZMJ", Region: "gru", Kind: KindHeld, Time: base.Add(4 * time.Minute)}
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
	if !found["00000000007M2BHZ0MP819C5RF"] {
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

// These pin the fixes for the ts-reviewer findings on PRs #127, #129 and #130.

// An idempotent replay of a decision whose durable copy never landed queues
// it again; one that is known durable is not republished.
func TestReplayedRecordRepublishesUntilDurable(t *testing.T) {
	sink := &fakeSink{failures: publishAttempts}
	journal := NewJournal(JournalConfig{Region: "gru", Sink: sink})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = journal.Run(ctx) }()
	decision := Decision{ID: "0000000000NV66QQK0A0C5BBG2", Kind: KindReleaseAdmitted, Summary: "admitted"}
	journal.Record(ctx, decision)
	waitFor(t, func() bool { return journal.Stats().PublishFailed == 1 })
	journal.Record(ctx, decision)
	waitFor(t, func() bool { return sink.count() == 1 })
	journal.Record(ctx, decision)
	time.Sleep(50 * time.Millisecond)
	if sink.count() != 1 || journal.Stats().Recorded != 1 {
		t.Fatalf("stored %d, recorded %d: a durable replay was published again or counted twice",
			sink.count(), journal.Stats().Recorded)
	}
}

// Memory evicts by arrival, so a memory page holding records older than an
// evicted one is not the newest page: the archive is consulted.
func TestOutOfOrderEvictionConsultsArchive(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	at := func(id string, minutes int) Decision {
		return Decision{ID: id, Region: "gru", Kind: KindHeld, Time: base.Add(time.Duration(minutes) * time.Minute)}
	}
	t3, t1, t2 := at("t3", 3), at("t1", 1), at("t2", 2)
	archive := &fakeArchive{complete: true, decisions: []Decision{t3, t1, t2}}
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 2, Archive: archive})
	for _, decision := range archive.decisions {
		journal.Ingest(decision)
	}
	result, err := journal.Query(t.Context(), Query{Limit: 1})
	if err != nil || len(result.Decisions) != 1 || result.Decisions[0].ID != "t3" {
		t.Fatalf("newest page = %+v (%v), want the evicted t3", result.Decisions, err)
	}
}

// A historical query reaches back from its own end, not from the memory
// boundary, so newer records cannot exhaust the scan budget first.
func TestHistoricalQueryAnchorsArchiveSearchAtUntil(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	old := Decision{ID: "old", Region: "gru", Kind: KindHeld, Time: base}
	archive := &fakeArchive{complete: true, decisions: []Decision{old}}
	for index := range maxArchiveScan + 10 {
		archive.decisions = append(archive.decisions, Decision{ID: fmt.Sprintf("n%06d", index), Region: "gru",
			Kind: KindHeld, Time: base.Add(30*24*time.Hour - time.Duration(maxArchiveScan-index)*time.Second)})
	}
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 1, Archive: archive})
	journal.MarkCoveredFrom(base.Add(30 * 24 * time.Hour))
	result, err := journal.Query(t.Context(), Query{Since: base.Add(-time.Hour), Until: base.Add(time.Hour)})
	if err != nil || len(result.Decisions) != 1 || result.Decisions[0].ID != "old" || result.Partial {
		t.Fatalf("historical query = %+v (%v)", result, err)
	}
}

// Every successful chain lookup during the replay is partial.
func TestChainDuringReplayIsPartial(t *testing.T) {
	journal := NewJournal(JournalConfig{Region: "gru"})
	decision := Decision{ID: NewID(), Region: "gru", Kind: KindHeld, Time: time.Now()}
	journal.Ingest(decision)
	journal.beginReplay()
	if chain, err := journal.Chain(t.Context(), decision.ID); err != nil || !chain.Partial {
		t.Fatalf("chain during replay = %+v (%v), want partial", chain, err)
	}
	journal.endReplay()
	if chain, err := journal.Chain(t.Context(), decision.ID); err != nil || chain.Partial {
		t.Fatalf("chain after replay = %+v (%v)", chain, err)
	}
}

// A peer's non-ASCII search text is a valid filter; control characters
// are not.
func TestRemoteFiltersAllowNonASCIIText(t *testing.T) {
	if !(remoteRequest{Version: wireVersion, Query: Query{Subject: "münchen"}}).valid() {
		t.Fatal("a non-ASCII subject filter was refused")
	}
	for _, value := range []string{"a\x7fb", "a\u0085b", "a\x01b"} {
		if (remoteRequest{Version: wireVersion, Query: Query{Subject: value}}).valid() {
			t.Fatalf("control character filter %q accepted", value)
		}
	}
}

// An oversized chain reply keeps its root and the requested decision and
// says it was trimmed.
func TestOversizedChainReplyKeepsRootAndRequested(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var decisions []Decision
	for index := range 40 {
		decisions = append(decisions, Decision{ID: fmt.Sprintf("c%03d", index), Region: "gru", Kind: KindHeld,
			Summary: strings.Repeat("x", 400), Time: base.Add(time.Duration(index) * time.Second)})
	}
	for index := 1; index < len(decisions); index++ {
		decisions[index].ParentID = decisions[0].ID
	}
	chain, _ := BuildChain(decisions, "c005")
	data, err := encodeReply(remoteReply{Version: wireVersion, Chain: &chain}, "c005", 4<<10)
	if err != nil {
		t.Fatal(err)
	}
	var reply remoteReply
	if err := json.Unmarshal(data, &reply); err != nil {
		t.Fatal(err)
	}
	if !reply.Chain.Truncated || !containsID(reply.Chain.Decisions, "c000") || !containsID(reply.Chain.Decisions, "c005") {
		t.Fatalf("trimmed chain lost its root or requested step: truncated=%v", reply.Chain.Truncated)
	}
}

// A caller-chosen ID encodes no time; once evicted from memory its chain is
// still found in the archive.
func TestChainFindsEvictedDeterministicIDInArchive(t *testing.T) {
	now := time.Now().UTC()
	admission := Decision{ID: "0000000000FKJSKJAEWPGR20W7", Region: "gru", Kind: KindReleaseAdmitted, Time: now.Add(-48 * time.Hour)}
	phase := Decision{ID: newIDAt(now.Add(-time.Hour)), Region: "gru", Kind: KindUpgradeStarted,
		ParentID: admission.ID, Time: now.Add(-time.Hour)}
	other := Decision{ID: newIDAt(now), Region: "gru", Kind: KindHeld, Time: now}
	archive := &fakeArchive{complete: true, decisions: []Decision{admission, phase, other}}
	journal := NewJournal(JournalConfig{Region: "gru", Capacity: 1, Archive: archive})
	for _, decision := range archive.decisions {
		journal.Ingest(decision)
	}
	for _, id := range []string{admission.ID, phase.ID} {
		chain, err := journal.Chain(t.Context(), id)
		if err != nil || chain.Root.ID != admission.ID || len(chain.Decisions) != 2 {
			t.Fatalf("chain of %s = %+v (%v)", id, chain, err)
		}
	}
}
