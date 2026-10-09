package authority

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestNetBirdStateRejectsStaleTransitionAndReadsThroughFollower(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	runtime, err := Start(t.Context(), js, Config{Scope: "gru", CandidateID: "25N2M1ND48SN1GD1DNCM8BTJFP", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	before, err := runtime.CommitNetBirdState(t.Context(), epoch, "0B2R51XPY68AE7SVFGZAGC8DGC", 0, []byte(`{"record":"install","command":"install"}`))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"record":"rollback","command":"rollback"}`)
	written, err := runtime.CommitNetBirdState(t.Context(), epoch, "2R6BD8J8358JYCZ2CXGD7KCE9M", before, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.CommitNetBirdState(t.Context(), epoch, "31AMKHTEKXAE8T964Z9TXZKCSG", before, []byte(`{"record":"confirm","command":"confirm"}`)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale transition error = %v, want conflict", err)
	}
	reader, err := OpenReader(t.Context(), js, "gru")
	if err != nil {
		t.Fatal(err)
	}
	state, err := reader.ReadNetBirdState(t.Context())
	if err != nil || state.Sequence != written || state.Epoch != epoch || !bytes.Equal(state.Payload, payload) {
		t.Fatalf("read-only follower state = %+v, %v", state, err)
	}
	if _, err := runtime.CommitHostMutation(t.Context(), epoch, MutationNetBirdState, netbirdStateKey, "generic-write", written, payload); err == nil {
		t.Fatal("generic host mutation accepted NetBird state")
	}
}

type netbirdHandoffPublisher struct {
	jetstream.JetStream
	beforePublish func(context.Context) error
	armed         atomic.Bool
}

func (js *netbirdHandoffPublisher) PublishMsg(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	if msg.Header.Get("TerraScale-Control-Kind") == string(MutationNetBirdState) && js.armed.Swap(false) {
		if err := js.beforePublish(ctx); err != nil {
			return nil, err
		}
	}
	return js.JetStream.PublishMsg(ctx, msg, opts...)
}

func TestNetBirdStateHandoffBetweenLeaseCheckAndPublishCannotReplaceSuccessor(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	wrapped := &netbirdHandoffPublisher{JetStream: js}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	old, err := Start(ctx, wrapped, Config{Scope: "gru", CandidateID: "052RQX6EM5DPGHCHJ230S9DCA0", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = old.Close() })
	// Keep the old local snapshot live while an independent durable handoff
	// occurs at precisely the last boundary before its state publication.
	old.cancel()
	<-old.done
	epoch := old.Current().Epoch
	before, err := old.CommitNetBirdState(ctx, epoch, "0B2R51XPY68AE7SVFGZAGC8DGC", 0, []byte(`{"record":"install","command":"install"}`))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"record":"rollback","command":"rollback"}`)
	var successor *Runtime
	wrapped.beforePublish = func(ctx context.Context) error {
		info, err := old.stream.Info(ctx)
		if err != nil {
			return err
		}
		entry, err := old.stream.GetLastMsgForSubject(ctx, old.leaseSub)
		if err != nil {
			return err
		}
		lease, err := decodeLease(entry.Data)
		if err != nil {
			return err
		}
		lease.Released, lease.TransitionID = true, entityid.New()
		wire, err := json.Marshal(lease)
		if err != nil {
			return err
		}
		if _, err := js.PublishMsg(ctx, controlMessage(old.leaseSub, "lease", lease.TransitionID, wire),
			jetstream.WithExpectLastSequence(info.State.LastSeq),
			jetstream.WithExpectLastSequenceForSubject(entry.Sequence, old.leaseSub)); err != nil {
			return err
		}
		successor, err = Start(ctx, js, Config{Scope: "gru", CandidateID: "5TE7PMMH4P1Q7NWYEWTAFK8SPH", Replicas: 1})
		if err != nil {
			return err
		}
		_, err = successor.CommitNetBirdState(ctx, successor.Current().Epoch, "2R6BD8J8358JYCZ2CXGD7KCE9M", before, payload)
		return err
	}
	wrapped.armed.Store(true)
	_, err = old.CommitNetBirdState(ctx, epoch, "31AMKHTEKXAE8T964Z9TXZKCSG", before, []byte(`{"record":"confirm","command":"confirm"}`))
	if successor != nil {
		t.Cleanup(func() { _ = successor.Close() })
	}
	if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrFenced) {
		t.Fatalf("old leader publication = %v, want fenced or conflict", err)
	}
	state, err := old.ReadNetBirdState(ctx)
	if err != nil || successor == nil || state.Epoch != successor.Current().Epoch || !bytes.Equal(state.Payload, payload) {
		t.Fatalf("old publication overwrote successor: %+v, %v", state, err)
	}
}

type netbirdExpiryStateRead struct {
	jetstream.Stream
	expires time.Time
}

func (s *netbirdExpiryStateRead) GetLastMsgForSubject(ctx context.Context, subject string) (*jetstream.RawStreamMsg, error) {
	entry, err := s.Stream.GetLastMsgForSubject(ctx, subject)
	if subject == mutationSubject("gru", MutationNetBirdState, netbirdStateKey) {
		timer := time.NewTimer(max(0, time.Until(s.expires.Add(time.Millisecond))))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return entry, err
}

func TestNetBirdStateLeaseExpiryDuringStateReadPreventsPublication(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	runtime, err := Start(t.Context(), js, Config{Scope: "gru", CandidateID: "7E0H8E1QQ6RX2WA68FZ892GDKP", Replicas: 1,
		LeaseDuration: time.Second, RenewInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	runtime.cancel()
	<-runtime.done
	snapshot := runtime.Current()
	runtime.stream = &netbirdExpiryStateRead{Stream: runtime.stream, expires: snapshot.ExpiresAt}
	if _, err := runtime.CommitNetBirdState(t.Context(), snapshot.Epoch, "7B23SVKMY5B2A1TBWCG39SDKKG", 0, []byte(`{"record":"install"}`)); !errors.Is(err, ErrFenced) {
		t.Fatalf("publication after lease expiry = %v, want fenced", err)
	}
	if _, err := runtime.ReadNetBirdState(t.Context()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired authority appended state: %v", err)
	}
}
