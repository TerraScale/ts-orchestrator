package authority

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

type countedHostStream struct {
	jetstream.Stream
	reads, baselines int
}

func (s *countedHostStream) GetMsg(ctx context.Context, seq uint64, opts ...jetstream.GetMsgOpt) (*jetstream.RawStreamMsg, error) {
	s.reads++
	return s.Stream.GetMsg(ctx, seq, opts...)
}

func (s *countedHostStream) GetLastMsgForSubject(ctx context.Context, subject string) (*jetstream.RawStreamMsg, error) {
	s.baselines++
	return s.Stream.GetLastMsgForSubject(ctx, subject)
}

func TestHostHistoryBoundsReadsByInventoryAndNewChanges(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	stream, err := openControlStream(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	subject := mutationSubject("gru", MutationDesired, "gru.node.api")
	record := controlRecord{Version: 1, Scope: "gru", Kind: MutationDesired, SubjectKey: "gru.node.api", OperationID: "0000000000FHEQV98X4ASD7RXW", Epoch: 1, Payload: []byte("active")}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var first *jetstream.PubAck
	for range 512 {
		first, err = js.Publish(t.Context(), subject, data)
		if err != nil {
			t.Fatal(err)
		}
	}
	info, err := stream.Info(t.Context(), jetstream.WithSubjectFilter("ts.control.gru.host.>"))
	if err != nil {
		t.Fatal(err)
	}
	counted := &countedHostStream{Stream: stream}
	var history HostHistory
	if err := history.Seed(t.Context(), counted, "gru", info); err != nil {
		t.Fatal(err)
	}
	from, to := history.since, time.Now().Add(time.Minute)
	for range 3 {
		got, err := history.Window(t.Context(), counted, "gru", from, to, first.Sequence)
		if err != nil || len(got) != 1 || got[0].Sequence != first.Sequence || string(got[0].Payload) != "active" {
			t.Fatalf("cached baseline = %+v, %v", got, err)
		}
	}
	if counted.baselines != 1 || counted.reads != 0 {
		t.Fatalf("lifetime churn was replayed: %d baseline reads, %d mutation reads", counted.baselines, counted.reads)
	}
	next, err := js.Publish(t.Context(), subject, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := history.Advance(t.Context(), counted, "gru", next.Sequence); err != nil {
		t.Fatal(err)
	}
	// A later cached mutation remains invisible to a pinned earlier read.
	got, err := history.Window(t.Context(), counted, "gru", from, to, first.Sequence)
	if err != nil || len(got) != 1 || got[0].Sequence != first.Sequence || counted.reads != 1 {
		t.Fatalf("pinned cache = %+v, %v, reads=%d", got, err, counted.reads)
	}
	invalid, err := js.Publish(t.Context(), subject, []byte(`{"version":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := history.Window(t.Context(), counted, "gru", from, to, invalid.Sequence); err == nil {
		t.Fatal("invalid committed history became an inventory answer")
	}
}

func TestHostHistoryExpiresAndReseedsWithoutLifetimeReplay(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	stream, err := openControlStream(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	counted := &countedHostStream{Stream: stream}
	var history HostHistory
	if err := history.Seed(t.Context(), counted, "gru", info); err != nil {
		t.Fatal(err)
	}
	initial := history.since
	if _, err := history.Window(t.Context(), counted, "gru", initial.Add(-time.Second), initial.Add(time.Minute), info.State.LastSeq); err == nil {
		t.Fatal("window preceding startup became available")
	}
	history.updated = initial.Add(-2 * time.Hour)
	if _, err := history.Window(t.Context(), counted, "gru", initial, initial.Add(time.Minute), info.State.LastSeq); err == nil {
		t.Fatal("expired checkpoint became available")
	}
	if err := history.Seed(t.Context(), counted, "gru", info); err != nil || !history.since.After(initial) || counted.reads != 0 {
		t.Fatalf("stale checkpoint was not reseeded: %+v %v", &history, err)
	}
	history.since = time.Now().Add(-2 * time.Hour)
	old := LogEntry{Kind: MutationDesired, SubjectKey: "gru.node.api", Epoch: 1, Sequence: 1, CreatedAt: history.since, Payload: []byte("active")}
	history.changes = []LogEntry{old}
	if err := history.Advance(t.Context(), counted, "gru", 0); err != nil || len(history.changes) != 0 || len(history.baseline) != 1 {
		t.Fatalf("expired mutations were not folded into baseline: %+v %v", &history, err)
	}
}

func TestHostHistoryLockHonorsRequestDeadline(t *testing.T) {
	var history HostHistory
	if err := history.lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { <-history.gate }()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err := history.lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cache lock ignored request deadline: %v", err)
	}
}
