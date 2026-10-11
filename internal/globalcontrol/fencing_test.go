package globalcontrol

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
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
					DatabaseID: "0000000000B703KMD4B8J6EWBB" + strconv.FormatUint(epoch, 10), PartitionID: "0000000000KJ432RJ85B7APRW2" + strconv.Itoa(index),
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

// TestConcurrentReadsAndAppends: a writer's appends and reads through its Reader
// share one stream handle, so appends must not rewrite that handle's cached
// info while reads use it (-race).
func TestConcurrentReadsAndAppends(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	js := newTestJetStream(t)
	writer, err := OpenHome(ctx, js, "gru", nil, 1, &pausedFencer{epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.PutRoster(ctx, 1, testRoster(1)); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	wait.Go(func() {
		for index := range 20 {
			entry := DirectoryEntry{DatabaseID: "0000000000B703KMD4B8J6EWBB", PartitionID: entityid.Derive("test-partition", strconv.Itoa(index)),
				HomeRegion: "gru", ActiveRegions: []string{"gru"}, Generation: 1}
			if _, err := writer.PutDirectory(ctx, 1, entry); err != nil {
				t.Error(err)
			}
		}
	})
	wait.Go(func() {
		for range 40 {
			if _, _, err := writer.Roster(ctx); err != nil {
				t.Error(err)
			}
		}
	})
	wait.Wait()
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

// Headerless records are rejected even before the first term barrier.
func TestHeaderlessRecordsBeforeTheFirstBarrierAreRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := newTestJetStream(t)
	writer, err := OpenHome(ctx, js, "gru", nil, 1, &pausedFencer{epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncodeJSON(testRoster(1))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := protocol.EncodeJSON(record{Version: recordVersion, Kind: KindRoster, Key: RosterKey, Generation: 1,
		Epoch: 1, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, subject(KindRoster, RosterKey), legacy); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writer.Roster(ctx); !errors.Is(err, ErrRecordCorrupt) {
		t.Fatalf("headerless record before the barrier = %v, want corruption", err)
	}
}

// TestMirrorWithFiniteLimitsIsRefused: an existing mirror that could discard
// home records does not pass verification.
func TestMirrorWithFiniteLimitsIsRefused(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*jetstream.StreamConfig){
		"max msgs":             func(config *jetstream.StreamConfig) { config.MaxMsgs = 10 },
		"max bytes":            func(config *jetstream.StreamConfig) { config.MaxBytes = 1 << 20 },
		"max msgs per subject": func(config *jetstream.StreamConfig) { config.MaxMsgsPerSubject = 1 },
	} {
		config := MirrorStreamConfig("gru", "sfo", 1)
		if err := verifyMirror(config, "gru", "sfo", 1); err != nil {
			t.Fatalf("expected mirror config refused: %v", err)
		}
		change(&config)
		if err := verifyMirror(config, "gru", "sfo", 1); err == nil {
			t.Errorf("%s: a mirror with a finite limit passed verification", name)
		}
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

// TestStreamVerificationRefusesTransformsAndLateMirrorStarts: a home stream
// that rewrites subjects, or a mirror that starts past the first record,
// is not accepted.
func TestStreamVerificationRefusesTransformsAndLateMirrorStarts(t *testing.T) {
	t.Parallel()
	home := HomeStreamConfig(1)
	home.SubjectTransform = &jetstream.SubjectTransformConfig{Source: "ts.global.v1.>", Destination: "elsewhere.>"}
	if err := verifyHome(home, 1); err == nil {
		t.Fatal("a home stream with a subject transform passed verification")
	}
	mirror := MirrorStreamConfig("gru", "sfo", 1)
	mirror.Mirror.OptStartSeq = 5
	if err := verifyMirror(mirror, "gru", "sfo", 1); err == nil {
		t.Fatal("a mirror starting past the first record passed verification")
	}
}
