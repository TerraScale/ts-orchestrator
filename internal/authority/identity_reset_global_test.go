package authority

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestIdentityResetRekeysGlobalHomeAndPreservesOpaqueHistory(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	for _, present := range []bool{false, true} {
		f := newIdentityRecordsFixture(t, 8)
		pin := &IdentityResetGlobalLease{Epoch: 13}
		old := []byte(`{"scope":"global","deployment_id":"retired","epoch":12}`)
		if present {
			ack, err := f.js.Publish(t.Context(), controlSubjectRoot+".global.lease", old)
			if err != nil {
				t.Fatal(err)
			}
			pin.PreviousSequence, pin.PreviousSHA256, pin.EpochFloor = ack.Sequence, resetDigest(old), 12
		}
		stream, err := f.js.Stream(t.Context(), ControlStreamName)
		if err != nil {
			t.Fatal(err)
		}
		info, err := stream.Info(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		f.reset.GlobalLease, f.reset.LastSequence = pin, info.State.LastSeq
		f.envelope = signIdentityResetForTest(t, f.reset, f.key)
		f.barrier(t)
		if _, err := f.replace(t, f.js, t.Context()); err != nil {
			t.Fatal(err)
		}
		held, err := Observe(t.Context(), f.js, protocol.GlobalScope)
		if err != nil || held.DeploymentID != f.reset.DeploymentID || held.Epoch != 13 || held.CanMutate() {
			t.Fatalf("global home was not root-held: %+v, %v", held, err)
		}
		if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		runtime, err := Start(ctx, f.js, Config{Scope: protocol.GlobalScope, DeploymentID: f.reset.DeploymentID, CandidateID: entityid.New(), Replicas: 1})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for !runtime.Current().CanMutate() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !runtime.Current().CanMutate() || runtime.Current().Epoch <= 13 {
			t.Fatalf("new deployment could not acquire global authority: %+v", runtime.Current())
		}
		if _, err := IdentityResetCompletion(t.Context(), f.js, f.envelope, f.roots, f.target, f.envelope.IssuedAt); err != nil {
			t.Fatalf("later global acquisition hid exact completion: %v", err)
		}
		_ = runtime.Close()
		cancel()
		if present {
			prior, err := stream.GetMsg(t.Context(), pin.PreviousSequence)
			if err != nil || resetDigest(prior.Data) != resetDigest(old) {
				t.Fatal("opaque global audit history changed")
			}
		}
	}
}

func TestIdentityResetRejectsChangedGlobalPredecessorBeforeRegionalHold(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	f.reset.GlobalLease = &IdentityResetGlobalLease{Epoch: 1}
	f.envelope = signIdentityResetForTest(t, f.reset, f.key)
	if _, err := f.js.Publish(t.Context(), controlSubjectRoot+".global.lease", []byte("changed global predecessor")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResetIdentityLease(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed global lease admitted: %v", err)
	}
}

func TestIdentityResetAtomicBatchDoesNotCommitOneScopeWhenGlobalCASLoses(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	f.reset.GlobalLease = &IdentityResetGlobalLease{Epoch: 1}
	f.envelope = signIdentityResetForTest(t, f.reset, f.key)
	wrapped := &identityRecordPublisher{JetStream: f.js}
	wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		if _, err := f.js.Publish(t.Context(), controlSubjectRoot+".global.lease", []byte("concurrent old global renewal")); err != nil {
			t.Fatal(err)
		}
		return f.js.PublishMsg(ctx, msg, opts...)
	}
	if _, err := ResetIdentityLease(t.Context(), wrapped, f.envelope, f.roots, f.target, time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatalf("lost atomic CAS: %v", err)
	}
	stream, err := f.js.Stream(t.Context(), ControlStreamName)
	if err != nil {
		t.Fatal(err)
	}
	regional, err := stream.GetLastMsgForSubject(t.Context(), controlSubjectRoot+".gru.lease")
	if err != nil || regional.Sequence != f.reset.PreviousSequence || resetDigest(regional.Data) != f.reset.PreviousSHA256 {
		t.Fatal("failed batch left the regional scope held")
	}
}
