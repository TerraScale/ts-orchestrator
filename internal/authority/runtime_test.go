package authority

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestStartReobservesCommittedLeaseAfterAmbiguousPublish(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	wrapped := &startupRetryJetStream{JetStream: js, fault: loseCommittedLeaseAck}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runtime, err := Start(ctx, wrapped, Config{
		Scope: "gru", CandidateID: "candidate-a", LeaseDuration: 5 * time.Second,
		RenewInterval: 2 * time.Second, Replicas: 1,
	})
	if err != nil {
		t.Fatalf("start authority after an ambiguous committed publish: %v", err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("close authority runtime: %v", err)
		}
	})

	snapshot := runtime.Current()
	if !snapshot.CanMutate() || snapshot.OwnerID != runtime.ownerID || snapshot.Epoch != 1 {
		t.Fatalf("runtime did not reobserve its committed lease under the same owner and epoch: %+v", snapshot)
	}
	if got := wrapped.leasePublishCalls.Load(); got != 2 {
		t.Fatalf("lease publish attempts = %d, want the committed attempt and one same-runtime renewal", got)
	}

	stream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		t.Fatalf("open authority stream observer: %v", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("inspect authority stream: %v", err)
	}
	if info.State.Msgs != 2 {
		t.Fatalf("authority stream contains %d records, want exactly two same-epoch lease barriers", info.State.Msgs)
	}
	for sequence := uint64(1); sequence <= info.State.Msgs; sequence++ {
		entry, err := stream.GetMsg(ctx, sequence)
		if err != nil {
			t.Fatalf("read lease barrier %d: %v", sequence, err)
		}
		lease, err := decodeLease(entry.Data)
		if err != nil {
			t.Fatalf("decode lease barrier %d: %v", sequence, err)
		}
		if lease.OwnerID != snapshot.OwnerID || lease.CandidateID != snapshot.CandidateID || lease.Epoch != snapshot.Epoch {
			t.Fatalf("lease barrier %d changed owner or epoch during retry: %+v", sequence, lease)
		}
	}
}

func TestStartDoesNotRetryPermanentOrCanceledLeasePublish(t *testing.T) {
	js := newAuthorityTestJetStream(t)

	t.Run("permanent authorization error", func(t *testing.T) {
		wrapped := &startupRetryJetStream{JetStream: js, fault: rejectLeasePublish}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		runtime, err := Start(ctx, wrapped, Config{
			Scope: "mia", CandidateID: "candidate-a", LeaseDuration: 5 * time.Second,
			RenewInterval: 2 * time.Second, Replicas: 1,
		})
		if runtime != nil {
			t.Fatal("Start returned a runtime after a rejected lease publish")
		}
		var apiErr *jetstream.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != 403 {
			t.Fatalf("Start error = %v, want the permanent authorization error", err)
		}
		if got := wrapped.leasePublishCalls.Load(); got != 1 {
			t.Fatalf("lease publish attempts after permanent error = %d, want 1", got)
		}
	})

	t.Run("caller cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		wrapped := &startupRetryJetStream{JetStream: js, fault: cancelLeasePublish, cancel: cancel}
		defer cancel()

		runtime, err := Start(ctx, wrapped, Config{
			Scope: "scl", CandidateID: "candidate-a", LeaseDuration: 5 * time.Second,
			RenewInterval: 2 * time.Second, Replicas: 1,
		})
		if runtime != nil {
			t.Fatal("Start returned a runtime after caller cancellation")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start error = %v, want context cancellation", err)
		}
		if got := wrapped.leasePublishCalls.Load(); got != 1 {
			t.Fatalf("lease publish attempts after cancellation = %d, want 1", got)
		}
	})
}

type startupRetryFault uint8

const (
	loseCommittedLeaseAck startupRetryFault = iota
	rejectLeasePublish
	cancelLeasePublish
)

type startupRetryJetStream struct {
	jetstream.JetStream
	fault             startupRetryFault
	cancel            context.CancelFunc
	leasePublishCalls atomic.Int32
	failOutcomeProbe  atomic.Bool
}

func (js *startupRetryJetStream) CreateStream(ctx context.Context, config jetstream.StreamConfig) (jetstream.Stream, error) {
	stream, err := js.JetStream.CreateStream(ctx, config)
	if err != nil {
		return nil, err
	}
	return &startupRetryStream{Stream: stream, jetStream: js}, nil
}

func (js *startupRetryJetStream) Stream(ctx context.Context, name string) (jetstream.Stream, error) {
	stream, err := js.JetStream.Stream(ctx, name)
	if err != nil {
		return nil, err
	}
	return &startupRetryStream{Stream: stream, jetStream: js}, nil
}

func (js *startupRetryJetStream) PublishMsg(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	if !strings.HasSuffix(msg.Subject, ".lease") {
		return js.JetStream.PublishMsg(ctx, msg, opts...)
	}
	call := js.leasePublishCalls.Add(1)
	switch js.fault {
	case loseCommittedLeaseAck:
		ack, err := js.JetStream.PublishMsg(ctx, msg, opts...)
		if err != nil || call != 1 {
			return ack, err
		}
		js.failOutcomeProbe.Store(true)
		return nil, jetstream.ErrNoStreamResponse
	case rejectLeasePublish:
		if call == 1 {
			return nil, &jetstream.APIError{Code: 403, ErrorCode: 10149, Description: "permission denied"}
		}
	case cancelLeasePublish:
		if call == 1 {
			js.cancel()
			return nil, jetstream.ErrNoStreamResponse
		}
	}
	return js.JetStream.PublishMsg(ctx, msg, opts...)
}

type startupRetryStream struct {
	jetstream.Stream
	jetStream *startupRetryJetStream
}

func (stream *startupRetryStream) GetLastMsgForSubject(ctx context.Context, subject string) (*jetstream.RawStreamMsg, error) {
	if strings.HasSuffix(subject, ".lease") && stream.jetStream.failOutcomeProbe.Swap(false) {
		return nil, jetstream.ErrNoStreamResponse
	}
	return stream.Stream.GetLastMsgForSubject(ctx, subject)
}

func newAuthorityTestJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream"),
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })

	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return js
}
