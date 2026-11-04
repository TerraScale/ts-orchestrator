package globalcontrol

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// pausedFencer models a leader whose lease Guard succeeded and which then
// paused: Guard keeps passing for its own epoch, so only the server-side term
// barrier can stop its writes.
type pausedFencer struct {
	mu    sync.Mutex
	epoch uint64
}

func (f *pausedFencer) Current() authority.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: protocol.GlobalScope, Epoch: f.epoch, Leader: true}
}

func (f *pausedFencer) Guard(_ context.Context, epoch uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if epoch == 0 || epoch != f.epoch {
		return authority.ErrFenced
	}
	return nil
}

func openFencedPair(ctx context.Context, t *testing.T) (jetstream.JetStream, *Writer, *Writer) {
	t.Helper()
	js := newTestJetStream(t)
	old, err := OpenHome(ctx, js, "gru", nil, 1, &pausedFencer{epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	next, err := OpenHome(ctx, js, "gru", nil, 1, &pausedFencer{epoch: 2})
	if err != nil {
		t.Fatal(err)
	}
	return js, old, next
}

// TestOldLeaderCannotCommitAfterNewTerm: a leader that passed its lease Guard
// and then paused cannot append once a newer term's barrier is in the global
// stream, whether the barrier lands before its reads or between its reads and
// its publish.
func TestOldLeaderCannotCommitAfterNewTerm(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	_, old, next := openFencedPair(ctx, t)

	if _, err := old.PutRoster(ctx, 1, testRoster(1)); err != nil {
		t.Fatal(err)
	}
	if term, err := old.Term(ctx); err != nil || term != 1 {
		t.Fatalf("term after first write = %d, %v", term, err)
	}

	// The new term's barrier lands after the old leader read and checked
	// everything, immediately before its conditional append.
	interleaved := false
	old.beforePublish = func() {
		if interleaved {
			return
		}
		interleaved = true
		if err := next.Fence(ctx, 2); err != nil {
			t.Errorf("new leader fence: %v", err)
		}
	}
	if _, err := old.PutRoster(ctx, 1, testRoster(2)); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("old leader write racing a new term = %v, want ErrFenced", err)
	}
	old.beforePublish = nil
	if !interleaved {
		t.Fatal("the new term never interleaved")
	}
	// A later attempt by the paused leader is fenced up front.
	if _, err := old.PutRoster(ctx, 1, testRoster(3)); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("old leader write after the new term = %v", err)
	}
	if err := old.Fence(ctx, 1); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("old leader re-fenced the stream back to its term: %v", err)
	}
	roster, _, err := next.Roster(ctx)
	if err != nil || roster.Generation != 1 {
		t.Fatalf("roster after fenced writes = %+v, %v", roster, err)
	}
	if _, err := next.PutRoster(ctx, 2, testRoster(2)); err != nil {
		t.Fatalf("new leader write: %v", err)
	}
	if term, err := next.Term(ctx); err != nil || term != 2 {
		t.Fatalf("term = %d, %v", term, err)
	}
}

// TestNewLeaderFirstWriteFencesTheOldTerm: the new leader does not need an
// explicit Fence; its first write appends the barrier.
func TestNewLeaderFirstWriteFencesTheOldTerm(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	_, old, next := openFencedPair(ctx, t)
	if _, err := old.PutRoster(ctx, 1, testRoster(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := next.PutRoster(ctx, 2, testRoster(2)); err != nil {
		t.Fatal(err)
	}
	entry := DirectoryEntry{DatabaseID: "00000000004SJMRETVW39JX054", PartitionID: "00000000003K6TBW31R91GBDRD", HomeRegion: "gru", ActiveRegions: []string{"gru"}, Generation: 1}
	if _, err := old.PutDirectory(ctx, 1, entry); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("old leader directory write after the new term = %v", err)
	}
	// An identical retry of a record the old leader did commit stays
	// idempotent only through the new leader; the old leader is fenced.
	if _, err := old.PutRoster(ctx, 1, testRoster(1)); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("old leader retry after the new term = %v", err)
	}
}

// TestForgedRecordsAreRejected: records without a matching epoch header and a
// forged term barrier are corruption, never state.
func TestForgedRecordsAreRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js, old, _ := openFencedPair(ctx, t)
	if _, err := old.PutRoster(ctx, 1, testRoster(1)); err != nil {
		t.Fatal(err)
	}
	stream, err := js.Stream(ctx, StreamName)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := stream.GetLastMsgForSubject(ctx, subject(KindRoster, RosterKey))
	if err != nil {
		t.Fatal(err)
	}
	// Replay the stored body under a different epoch header.
	forged := nats.NewMsg(subject(KindRoster, RosterKey))
	forged.Data = stored.Data
	forged.Header.Set(EpochHeader, "7")
	if _, err := js.PublishMsg(ctx, forged); err != nil {
		t.Fatal(err)
	}
	if _, _, err := old.Roster(ctx); !errors.Is(err, ErrRecordCorrupt) {
		t.Fatalf("record with a mismatched epoch header = %v", err)
	}
	if _, err := js.Publish(ctx, subject(KindTerm, termKey), []byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Term(ctx); !errors.Is(err, ErrRecordCorrupt) {
		t.Fatalf("forged term barrier = %v", err)
	}
	if _, err := old.PutRoster(ctx, 1, testRoster(2)); err == nil {
		t.Fatal("writer appended over a corrupt term barrier")
	}
}

// TestEmptyMirrorWithoutHomeContactFailsClosed: an empty mirror that never
// heard from the home stream cannot answer "not found".
func TestEmptyMirrorWithoutHomeContactFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := newTestJetStream(t)
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "EMPTY_MIRROR_PROBE", Subjects: []string{"probe.>"}})
	if err != nil {
		t.Fatal(err)
	}
	reader := &Reader{stream: stream, js: js, mirror: true}
	if _, _, err := reader.Roster(ctx); !errors.Is(err, ErrMirrorNotCaughtUp) {
		t.Fatalf("empty unconfirmed mirror read = %v, want ErrMirrorNotCaughtUp", err)
	}
	if _, err := reader.Term(ctx); !errors.Is(err, ErrMirrorNotCaughtUp) {
		t.Fatalf("empty unconfirmed mirror term = %v, want ErrMirrorNotCaughtUp", err)
	}
}
