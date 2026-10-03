package globalcontrol

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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
	return authority.Snapshot{Scope: protocol.GlobalScope, Epoch: f.epoch, Leader: true}
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
	entry := DirectoryEntry{DatabaseID: "db-1", PartitionID: "p0", HomeRegion: "gru", ActiveRegions: []string{"gru"}, Generation: 1}
	if _, err := old.PutDirectory(ctx, 1, entry); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("old leader directory write after the new term = %v", err)
	}
	// An identical retry of a record the old leader did commit stays
	// idempotent only through the new leader; the old leader is fenced.
	if _, err := old.PutRoster(ctx, 1, testRoster(1)); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("old leader retry after the new term = %v", err)
	}
}

// TestConcurrentWritersNeverInterleaveTerms: two leaders hammer the stream;
// once epoch 2's barrier is stored, no epoch 1 record follows it.
func TestConcurrentWritersNeverInterleaveTerms(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	js, old, next := openFencedPair(ctx, t)
	if _, err := next.PutRoster(ctx, 2, testRoster(1)); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for writer, epoch := range map[*Writer]uint64{old: 1, next: 2} {
		wait.Go(func() {
			for index := range 20 {
				entry := DirectoryEntry{
					DatabaseID: "db-" + strconv.FormatUint(epoch, 10), PartitionID: "p" + strconv.Itoa(index),
					HomeRegion: "gru", ActiveRegions: []string{"gru"}, Generation: 1,
				}
				_, _ = writer.PutDirectory(ctx, epoch, entry)
			}
		})
	}
	wait.Wait()
	stream, err := js.Stream(ctx, StreamName)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var term uint64
	for sequence := uint64(1); sequence <= info.State.LastSeq; sequence++ {
		message, err := stream.GetMsg(ctx, sequence)
		if err != nil {
			t.Fatal(err)
		}
		epoch, err := strconv.ParseUint(message.Header.Get(EpochHeader), 10, 64)
		if err != nil {
			t.Fatalf("record %d has no epoch header", sequence)
		}
		if message.Subject == subject(KindTerm, termKey) {
			term = epoch
			continue
		}
		if epoch != term {
			t.Fatalf("record %d of epoch %d was committed in term %d", sequence, epoch, term)
		}
	}
	if term != 2 {
		t.Fatalf("final term = %d", term)
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

// TestHomeRemovesMirrorConsumersOfRemovedPeers: dropping a peer from the
// interregion configuration deletes its durable mirror consumer on reopen.
func TestHomeRemovesMirrorConsumersOfRemovedPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := newTestJetStream(t)
	fencer := &pausedFencer{epoch: 1}
	if _, err := OpenHome(ctx, js, "gru", []string{"fra", "iad", "sfo"}, 1, fencer); err != nil {
		t.Fatal(err)
	}
	assertMirrorConsumers(ctx, t, js, []string{"fra", "iad", "sfo"})
	stream, err := js.Stream(ctx, StreamName)
	if err != nil {
		t.Fatal(err)
	}
	// A non-mirror consumer is not the writer's to delete.
	if _, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{Durable: "audit", AckPolicy: jetstream.AckExplicitPolicy}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHome(ctx, js, "gru", []string{"sfo"}, 1, fencer); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []string{"fra", "iad"} {
		if _, err := stream.Consumer(ctx, protocol.GlobalMirrorConsumer(peer)); !errors.Is(err, jetstream.ErrConsumerNotFound) {
			t.Fatalf("removed peer %s consumer = %v", peer, err)
		}
	}
	if _, err := stream.PushConsumer(ctx, protocol.GlobalMirrorConsumer("sfo")); err != nil {
		t.Fatalf("kept peer consumer: %v", err)
	}
	if _, err := stream.Consumer(ctx, "audit"); err != nil {
		t.Fatalf("unrelated consumer was deleted: %v", err)
	}
}
