package authority

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestUsageJournalRetainsExactCommitsAcrossHistoryRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	js := newAuthorityTestJetStream(t)
	runtime, err := Start(ctx, js, Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	key := "gru.host-a"
	if _, err := runtime.CommitHostMutation(ctx, epoch, MutationUsageObservation, key, entityid.New(), 0, []byte("unverified")); err == nil {
		t.Fatal("usage journal accepted an unverified append")
	}
	if _, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationUsageObservation, key, entityid.New(), 0, []byte("fenced"),
		func(ctx context.Context) error { return runtime.Guard(ctx, epoch+1) }); !errors.Is(err, ErrFenced) {
		t.Fatalf("usage journal ignored actual authority fencing: %v", err)
	}
	stream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		t.Fatal(err)
	}
	var sequences []uint64
	var committed []LogEntry
	var previous uint64
	for _, payload := range []string{"initial resources", "replacement resources"} {
		var escaped context.Context
		sequence, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationUsageObservation, key, entityid.New(), previous, []byte(payload),
			func(ctx context.Context) error {
				escaped = ctx
				return runtime.Guard(ctx, epoch)
			})
		if err != nil {
			t.Fatal(err)
		}
		if escaped == nil || escaped.Err() == nil || !errors.Is(runtime.Guard(escaped, epoch), ErrFenced) {
			t.Fatal("verified mutation guard escaped its callback lifetime")
		}
		previous = sequence
		raw, err := stream.GetMsg(ctx, sequence)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := DecodeUsageObservationEntry(raw, "gru")
		if err != nil || entry.Sequence != sequence || entry.Epoch != epoch || string(entry.Payload) != payload || entry.CreatedAt != raw.Time {
			t.Fatalf("usage commit lost server timestamp/resource identity: %+v %v", entry, err)
		}
		sequences = append(sequences, sequence)
		committed = append(committed, entry)
	}
	for range 2 {
		var restarted HostHistory
		entries, err := restarted.UsageWindow(ctx, stream, "gru", previous)
		if err != nil || !slices.EqualFunc(entries, committed, func(a, b LogEntry) bool {
			return a.Sequence == b.Sequence && a.CreatedAt.Equal(b.CreatedAt) && a.Epoch == b.Epoch && a.SubjectKey == b.SubjectKey && slices.Equal(a.Payload, b.Payload)
		}) {
			t.Fatalf("restart rewrote or backfilled committed usage: %+v %v; sequences=%v", entries, err, sequences)
		}
		pinned, err := restarted.UsageWindow(ctx, stream, "gru", sequences[0])
		if err != nil || len(pinned) != 1 || pinned[0].Sequence != sequences[0] {
			t.Fatalf("pinned history substituted a later resource record: %+v %v", pinned, err)
		}
	}
}
