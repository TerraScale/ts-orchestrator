package delivery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

type testCodec struct{}

type interceptedPublish struct {
	jetstream.JetStream
	publish func(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

func (js *interceptedPublish) Publish(ctx context.Context, subject string, payload []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	return js.publish(ctx, subject, payload, opts...)
}

type overriddenAdmissionGet struct {
	jetstream.KeyValue
	get func(context.Context, string) (jetstream.KeyValueEntry, error)
}

func (kv overriddenAdmissionGet) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	return kv.get(ctx, key)
}

type publishCall struct {
	subject string
	payload []byte
}

func recordPublishCall(calls *[]publishCall, subject string, payload []byte) {
	*calls = append(*calls, publishCall{subject: subject, payload: bytes.Clone(payload)})
}

func (testCodec) Sign(_ context.Context, payload []byte) ([]byte, error) { return payload, nil }
func (testCodec) Verify(_ context.Context, wire []byte) (VerifiedEnvelope, error) {
	return VerifiedEnvelope{Payload: wire, Actor: "operator"}, nil
}
func (testCodec) SignArtifact(_ context.Context, record ArtifactRecord) ([]byte, error) {
	return json.Marshal(record)
}
func (testCodec) VerifyArtifact(_ context.Context, wire []byte) (ArtifactRecord, string, error) {
	var r ArtifactRecord
	err := json.Unmarshal(wire, &r, json.RejectUnknownMembers(true))
	return r, "operator", err
}
func (c testCodec) VerifyArchivedArtifact(ctx context.Context, wire []byte) (ArtifactRecord, string, error) {
	return c.VerifyArtifact(ctx, wire)
}

type testFence struct{}

func (testFence) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
}

func (testFence) Guard(_ context.Context, epoch uint64) error {
	if epoch != 1 {
		return errors.New("fenced")
	}
	return nil
}

type testStandbyFence struct{ leader atomic.Bool }

type failingFetchConsumer struct {
	jetstream.Consumer
	err        error
	batchErr   bool
	failAlways bool
	calls      atomic.Int32
}

func (c *failingFetchConsumer) Fetch(batch int, opts ...jetstream.FetchOpt) (jetstream.MessageBatch, error) {
	if c.calls.Add(1) == 1 || c.failAlways {
		if c.batchErr {
			messages := make(chan jetstream.Msg)
			close(messages)
			return failedMessageBatch{messages: messages, err: c.err}, nil
		}
		return nil, c.err
	}
	return c.Consumer.Fetch(batch, opts...)
}

type failedMessageBatch struct {
	messages <-chan jetstream.Msg
	err      error
}

func (b failedMessageBatch) Messages() <-chan jetstream.Msg { return b.messages }
func (b failedMessageBatch) Error() error                   { return b.err }

type failingAckConsumer struct {
	jetstream.Consumer
	wrapped atomic.Bool
	ackErr  chan struct{}
}

func (c *failingAckConsumer) Fetch(batchSize int, opts ...jetstream.FetchOpt) (jetstream.MessageBatch, error) {
	batch, err := c.Consumer.Fetch(batchSize, opts...)
	if err != nil || c.wrapped.Swap(true) {
		return batch, err
	}
	messages := make(chan jetstream.Msg, 1)
	go func() {
		defer close(messages)
		for msg := range batch.Messages() {
			messages <- failingAckMsg{Msg: msg, failed: c.ackErr}
		}
	}()
	return ackFailureBatch{MessageBatch: batch, messages: messages}, nil
}

type ackFailureBatch struct {
	jetstream.MessageBatch
	messages <-chan jetstream.Msg
}

func (b ackFailureBatch) Messages() <-chan jetstream.Msg { return b.messages }

type failingAckMsg struct {
	jetstream.Msg
	failed chan struct{}
}

func (m failingAckMsg) Ack() error {
	close(m.failed)
	return jetstream.ErrServerShutdown
}

func (f *testStandbyFence) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: f.leader.Load(), Leader: f.leader.Load(), Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
}

func (f *testStandbyFence) Guard(_ context.Context, epoch uint64) error {
	if !f.leader.Load() {
		return authority.ErrNotLeader
	}
	if epoch != 1 {
		return authority.ErrFenced
	}
	return nil
}

type testPlanner struct{}

func (testPlanner) Plan(_ context.Context, i Intent) ([]host.Desired, error) {
	return []host.Desired{{Cell: i.Cell, Node: "node-one", Environment: i.Environment, Role: i.Role, Digest: i.ArtifactDigest, Generation: i.Generation, AuthorityEpoch: i.AuthorityEpoch}}, nil
}

type testWriter struct {
	mu            sync.Mutex
	calls         int
	failFirst     bool
	cancelFirst   bool
	fenceFirst    bool
	conflictFirst bool
}

func (w *testWriter) ApplyDesired(_ context.Context, d host.Desired) (host.Receipt, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	if w.failFirst && w.calls == 1 {
		return host.Receipt{}, errors.New("transient host failure")
	}
	if w.cancelFirst && w.calls == 1 {
		return host.Receipt{}, context.Canceled
	}
	if w.fenceFirst && w.calls == 1 {
		return host.Receipt{}, authority.ErrFenced
	}
	if w.conflictFirst && w.calls == 1 {
		return host.Receipt{}, host.ErrDesiredConflict
	}
	return host.Receipt{Generation: d.Generation, Revision: uint64(w.calls)}, nil
}
func (w *testWriter) count() int { w.mu.Lock(); defer w.mu.Unlock(); return w.calls }

func testService(t *testing.T, writer *testWriter) (*Service, context.Context) {
	s, _, ctx := testServiceWithRuntime(t, writer)
	return s, ctx
}

func testServiceWithRuntime(t *testing.T, writer *testWriter) (*Service, *deliveryTestBroker, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	r := startDeliveryTestBroker(t, ctx)
	t.Cleanup(func() { _ = r.Close() })
	s, err := Open(ctx, Config{Conn: r.Conn(), JS: r.JetStream(), Cell: "lab", Replicas: 1, Signer: testCodec{}, Verifier: testCodec{}, ArtifactSigner: testCodec{}, ArtifactVerifier: testCodec{}, AuthorizeArtifact: func(context.Context, string, ArtifactRecord) error { return nil }, Authorize: func(context.Context, string, Intent) error { return nil }, Fencer: testFence{}, Planner: testPlanner{}, Writer: writer})
	if err != nil {
		t.Fatal(err)
	}
	return s, r, ctx
}

func testIntent(t *testing.T, s *Service, ctx context.Context) Intent {
	t.Helper()
	source := ArtifactSource{Repository: "https://github.com/TerraScale/ts-orchestrator", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TreeDigest: hex.EncodeToString(sha256.New().Sum(nil))}
	request := ArtifactClaimRequest{Source: source, Cell: "lab", Role: "worker", Environment: "production"}
	artifact, wire, err := s.PrepareArtifact(ctx, bytes.NewReader([]byte("#!/bin/sh\necho ready\n")), request)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err = s.AcceptArtifactClaim(ctx, wire)
	if err != nil {
		t.Fatal(err)
	}
	return Intent{SchemaVersion: SchemaVersion, OperationID: "0000000000EF7XYFTYFG8Q39NY", Source: source, ArtifactDigest: artifact.Digest, ManifestDigest: artifact.ManifestDigest, Cell: "lab", Role: "worker", Environment: "production", Generation: 1, DesiredReplicas: 1, ConfigDigest: ConfigDigestOf(nil, nil, nil), AuthorityEpoch: 1}
}

func TestSubmitOperationReadRetriesTransientLeaderFailure(t *testing.T) {
	want := &operationValue{value: []byte("durable operation"), revision: 7}
	calls := 0
	got, err := retrySubmitOperationRead(t.Context(), func(context.Context) (*operationValue, error) {
		calls++
		if calls == 1 {
			return nil, &nats.APIError{Code: 503, ErrorCode: 10008, Description: "JetStream system temporarily unavailable"}
		}
		return want, nil
	})
	if err != nil || got != want || calls != 2 {
		t.Fatalf("operation leader read after failover: value=%v error=%v calls=%d, want value and two attempts", got, err, calls)
	}
}

func TestSubmitOperationReadUsesRecoveryBudgetAfterFiveTransientFailures(t *testing.T) {
	want := &operationValue{value: []byte("durable operation"), revision: 7}
	calls := 0
	got, err := retrySubmitOperationRead(t.Context(), func(context.Context) (*operationValue, error) {
		calls++
		if calls <= 5 {
			return nil, &nats.APIError{Code: 503, ErrorCode: 10008, Description: "JetStream system temporarily unavailable"}
		}
		return want, nil
	})
	if err != nil || got != want || calls != 6 {
		t.Fatalf("operation leader read after recovery: value=%v error=%v calls=%d, want value and six attempts", got, err, calls)
	}
}

func TestSubmitOperationReadPreservesPermanentErrorsAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"permission denied", nats.ErrPermissionViolation},
		{"JetStream disabled", &nats.APIError{Code: 503, ErrorCode: 10076}},
		{"missing operation", jetstream.ErrKeyNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			_, err := retrySubmitOperationRead(t.Context(), func(context.Context) (*operationValue, error) {
				calls++
				return nil, test.err
			})
			if !errors.Is(err, test.err) || calls != 1 {
				t.Fatalf("operation read error=%v calls=%d, want immediate %v", err, calls, test.err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	_, err := retrySubmitOperationRead(ctx, func(context.Context) (*operationValue, error) {
		calls++
		cancel()
		return nil, nats.ErrTimeout
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled operation read error=%v calls=%d, want caller cancellation", err, calls)
	}
}

func TestSubmitRetriesTransientPublishWithSameSignedPayload(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	intent := testIntent(t, service, ctx)
	calls := make([]publishCall, 0, 2)
	service.js = &interceptedPublish{JetStream: service.js, publish: func(_ context.Context, subject string, payload []byte, _ ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		recordPublishCall(&calls, subject, payload)
		if len(calls) == 1 {
			return nil, jetstream.ErrNoStreamResponse
		}
		return &jetstream.PubAck{}, nil
	}}

	if err := service.Submit(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("publish attempts=%d, want 2", len(calls))
	}
	if calls[0].subject != IntentSubject(intent.Cell) || calls[1].subject != calls[0].subject {
		t.Fatalf("publish subjects changed across retry: %q, %q", calls[0].subject, calls[1].subject)
	}
	if !bytes.Equal(calls[0].payload, calls[1].payload) {
		t.Fatal("signed payload changed across retry")
	}
}

func TestSubmitRetriesOtherTypedTransientPublishErrors(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	intent := testIntent(t, service, ctx)
	for index, transientErr := range []error{nats.ErrNoResponders, nats.ErrTimeout, nats.ErrDisconnected, nats.ErrNoServers} {
		t.Run(transientErr.Error(), func(t *testing.T) {
			calls := 0
			service.js = &interceptedPublish{JetStream: service.js, publish: func(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
				calls++
				if calls == 1 {
					return nil, transientErr
				}
				return &jetstream.PubAck{}, nil
			}}
			attempt := intent
			attempt.OperationID = entityid.Derive("test-delivery", fmt.Sprintf("transient-%d", index))
			if err := service.Submit(ctx, attempt); err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatalf("publish attempts=%d, want 2", calls)
			}
		})
	}
}

func TestSubmitRetriesWhenPublishAttemptDeadlineExpires(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	intent := testIntent(t, service, ctx)
	calls := 0
	service.js = &interceptedPublish{JetStream: service.js, publish: func(publishCtx context.Context, _ string, _ []byte, _ ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		calls++
		if calls == 1 {
			<-publishCtx.Done()
			return nil, publishCtx.Err()
		}
		return &jetstream.PubAck{}, nil
	}}
	if err := service.Submit(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil || calls != 2 {
		t.Fatalf("parent context error=%v publish attempts=%d, want valid parent and 2 attempts", ctx.Err(), calls)
	}
}

func TestSubmitRetryAfterAmbiguousAckUsesJetStreamDeduplication(t *testing.T) {
	writer := &testWriter{}
	service, _, ctx := testServiceWithRuntime(t, writer)
	intent := testIntent(t, service, ctx)
	calls := make([]publishCall, 0, 2)
	acks := make([]*jetstream.PubAck, 0, 2)
	base := service.js
	service.js = &interceptedPublish{JetStream: base, publish: func(publishCtx context.Context, subject string, payload []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		recordPublishCall(&calls, subject, payload)
		ack, err := base.Publish(publishCtx, subject, payload, opts...)
		if err != nil {
			return nil, err
		}
		acks = append(acks, ack)
		if len(calls) == 1 {
			return nil, jetstream.ErrNoStreamResponse
		}
		return ack, nil
	}}

	if err := service.Submit(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || len(acks) != 2 {
		t.Fatalf("publish attempts=%d acknowledgements=%d, want two each", len(calls), len(acks))
	}
	if acks[0].Sequence != acks[1].Sequence || !acks[1].Duplicate {
		t.Fatalf("retry acknowledgement did not deduplicate: first=%+v second=%+v", acks[0], acks[1])
	}
	if calls[0].subject != calls[1].subject || !bytes.Equal(calls[0].payload, calls[1].payload) {
		t.Fatal("ambiguous publish retry changed subject or signed payload")
	}
	stream, err := base.Stream(ctx, IntentStream)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Fatalf("ambiguous retry stored %d messages, want one", info.State.Msgs)
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- service.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		receipt, err := service.Status(ctx, intent.OperationID)
		if err == nil {
			if receipt.Status != "accepted" || writer.count() != 1 {
				t.Fatalf("receipt=%+v desired writes=%d", receipt, writer.count())
			}
			break
		}
		if !errors.Is(err, ErrPending) {
			t.Fatal(err)
		}
		select {
		case <-deadline.C:
			t.Fatal("deduplicated delivery did not complete")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestSubmitRetriesNoStreamResponseThroughLeaderRecoveryWithSameMessageID(t *testing.T) {
	service, _, ctx := testServiceWithRuntime(t, &testWriter{})
	intent := testIntent(t, service, ctx)
	base := service.js
	calls := make([]publishCall, 0, 6)
	acks := make([]*jetstream.PubAck, 0, 6)
	service.js = &interceptedPublish{JetStream: base, publish: func(publishCtx context.Context, subject string, payload []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		recordPublishCall(&calls, subject, payload)
		ack, err := base.Publish(publishCtx, subject, payload, opts...)
		if err != nil {
			return nil, err
		}
		acks = append(acks, ack)
		if len(calls) <= 5 {
			return nil, jetstream.ErrNoStreamResponse
		}
		return ack, nil
	}}

	if err := service.Submit(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 6 || len(acks) != 6 {
		t.Fatalf("publish attempts=%d acknowledgements=%d, want six each", len(calls), len(acks))
	}
	for index, call := range calls {
		if call.subject != IntentSubject(intent.Cell) || !bytes.Equal(call.payload, calls[0].payload) {
			t.Fatalf("publish attempt %d changed subject or signed payload", index)
		}
		if acks[index].Sequence != acks[0].Sequence || index > 0 && !acks[index].Duplicate {
			t.Fatalf("publish attempt %d did not deduplicate with the same message ID: first=%+v current=%+v", index, acks[0], acks[index])
		}
	}
	stream, err := base.Stream(ctx, IntentStream)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Fatalf("retries stored %d messages, want one", info.State.Msgs)
	}
}

func TestSubmitPublishStopsAtCallerDeadlineAndCancellation(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	intent := testIntent(t, service, ctx)
	calls := 0
	service.js = &interceptedPublish{JetStream: service.js, publish: func(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		calls++
		return nil, nats.ErrNoResponders
	}}
	deadlineCtx, stop := context.WithTimeout(ctx, 350*time.Millisecond)
	defer stop()
	if err := service.publishIntent(deadlineCtx, IntentSubject(intent.Cell), []byte("signed intent"), "deadline-publish"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller deadline error=%v, want deadline exceeded", err)
	}
	if calls == 0 {
		t.Fatal("publish did not attempt before caller deadline")
	}

	started := make(chan struct{})
	calls = 0
	service.js = &interceptedPublish{JetStream: service.js, publish: func(publishCtx context.Context, _ string, _ []byte, _ ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		calls++
		close(started)
		<-publishCtx.Done()
		return nil, publishCtx.Err()
	}}
	canceledCtx, cancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { result <- service.Submit(canceledCtx, intent) }()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation error=%v", err)
	}
	if calls != 1 {
		t.Fatalf("publish attempts after caller cancellation=%d, want 1", calls)
	}
}

func TestSubmitPublishStopsImmediatelyForPermanentErrors(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	intent := testIntent(t, service, ctx)
	tests := []struct {
		name string
		err  error
	}{
		{name: "JetStream disabled", err: jetstream.ErrJetStreamNotEnabled},
		{name: "JetStream disabled for account", err: jetstream.ErrJetStreamNotEnabledForAccount},
		{name: "missing stream", err: jetstream.ErrStreamNotFound},
		{name: "invalid acknowledgement", err: jetstream.ErrInvalidJSAck},
		{name: "invalid publish option", err: jetstream.ErrInvalidOption},
		{name: "permission denied", err: nats.ErrPermissionViolation},
		{name: "API 4xx", err: &jetstream.APIError{Code: 400, Description: "bad request"}},
		{name: "unknown", err: errors.New("unclassified publish failure")},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			service.js = &interceptedPublish{JetStream: service.js, publish: func(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
				calls++
				return nil, test.err
			}}
			attempt := intent
			attempt.OperationID = entityid.Derive("test-delivery", fmt.Sprintf("permanent-%d", index))
			if err := service.Submit(ctx, attempt); !errors.Is(err, test.err) {
				t.Fatalf("Submit error=%v, want %v", err, test.err)
			}
			if calls != 1 {
				t.Fatalf("publish attempts=%d, want 1", calls)
			}
		})
	}
}

func TestSubmitPublishRetriesGenericAPI5xxButNotJetStreamDisabledCodes(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	intent := testIntent(t, service, ctx)
	calls := 0
	service.js = &interceptedPublish{JetStream: service.js, publish: func(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		calls++
		if calls == 1 {
			return nil, &jetstream.APIError{Code: 503, Description: "temporary service failure"}
		}
		return &jetstream.PubAck{}, nil
	}}
	if err := service.Submit(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("generic API 5xx attempts=%d, want 2", calls)
	}

	for index, test := range []struct {
		name string
		err  error
	}{
		{name: "JetStream disabled", err: jetstream.ErrJetStreamNotEnabled},
		{name: "JetStream disabled for account", err: jetstream.ErrJetStreamNotEnabledForAccount},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			service.js = &interceptedPublish{JetStream: service.js, publish: func(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
				calls++
				return nil, test.err
			}}
			attempt := intent
			attempt.OperationID = entityid.Derive("test-delivery", fmt.Sprintf("disabled-%d", index))
			if err := service.Submit(ctx, attempt); !errors.Is(err, test.err) {
				t.Fatalf("Submit error=%v, want %v", err, test.err)
			}
			if calls != 1 {
				t.Fatalf("publish attempts=%d, want 1", calls)
			}
		})
	}
}

func TestArtifactAdmissionBindsSourceAndReadback(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	client, err := ConnectClient(ctx, Config{Conn: s.config.Conn, JS: s.js, Cell: "lab", ArtifactSigner: testCodec{}, ArtifactVerifier: testCodec{}, AuthorizeArtifact: func(context.Context, string, ArtifactRecord) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Run(ctx); err == nil {
		t.Fatal("client unexpectedly started a consumer")
	}
	i := testIntent(t, s, ctx)
	r, err := client.readAdmission(ctx, i.ArtifactDigest, i.Cell, i.Role, i.Environment)
	if err != nil || r.ManifestDigest != i.ManifestDigest {
		t.Fatalf("admission: %+v %v", r, err)
	}
	other := i.Source
	other.Commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	_, wire, err := s.PrepareArtifact(ctx, bytes.NewReader([]byte("#!/bin/sh\necho ready\n")), ArtifactClaimRequest{Source: other, Cell: "lab", Role: "worker", Environment: "production"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptArtifactClaim(ctx, wire); !errors.Is(err, ErrConflict) {
		t.Fatalf("same bytes with different source: %v", err)
	}
	if err := s.verifyArtifact(ctx, r); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactClaimMustBeFreshForAdmissionButRemainsReadable(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 24, 9, 0, 0, 0, time.UTC)
	codec := Ed25519Codec{Cell: "lab", Actor: "operator", PrivateKey: priv, Trusted: map[string]TrustedSigner{keyID: {Actor: "operator", PublicKey: pub}}, Lifetime: time.Minute, MaxLifetime: time.Minute, Now: func() time.Time { return now }}
	s.config.ArtifactSigner = codec
	s.config.ArtifactVerifier = codec
	source := ArtifactSource{Repository: "https://github.com/TerraScale/ts-orchestrator", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TreeDigest: hex.EncodeToString(sha256.New().Sum(nil))}
	record, wire, err := s.PrepareArtifact(ctx, bytes.NewReader([]byte("artifact bytes")), ArtifactClaimRequest{Source: source, Cell: "lab", Role: "worker", Environment: "production"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.AcceptArtifactClaim(ctx, wire); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired claim was admitted: %v", err)
	}
	if _, err := s.readAdmission(ctx, record.Digest, record.Cell, record.Role, record.Environment); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("expired claim created admission: %v", err)
	}
	now = now.Add(-2 * time.Minute)
	if admitted, err := s.AcceptArtifactClaim(ctx, wire); err != nil || admitted != record {
		t.Fatalf("fresh claim admission=%+v err=%v", admitted, err)
	}
	now = now.Add(2 * time.Minute)
	if admitted, err := s.readAdmission(ctx, record.Digest, record.Cell, record.Role, record.Environment); err != nil || admitted != record {
		t.Fatalf("archived claim admission=%+v err=%v", admitted, err)
	}
}

func TestDurableRetryReplayAndOperationConflict(t *testing.T) {
	w := &testWriter{failFirst: true}
	s, ctx := testService(t, w)
	i := testIntent(t, s, ctx)
	if err := s.Submit(ctx, i); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	for {
		receipt, err := s.Status(ctx, i.OperationID)
		if err == nil {
			if receipt.Status != "accepted" || receipt.Fingerprint == "" || w.count() < 2 {
				t.Fatalf("receipt=%+v calls=%d", receipt, w.count())
			}
			break
		}
		if !errors.Is(err, ErrPending) {
			t.Fatal(err)
		}
		select {
		case <-deadline.C:
			t.Fatalf("delivery never retried; calls=%d", w.count())
		case <-time.After(30 * time.Millisecond):
		}
	}
	before := w.count()
	b, err := testCodec{}.Sign(ctx, mustJSON(i))
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := s.process(ctx, b)
	if err != nil || !terminal || w.count() != before {
		t.Fatalf("replay terminal=%t err=%v calls=%d", terminal, err, w.count())
	}
	i.Generation++
	if err := s.Submit(ctx, i); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting operation: %v", err)
	}
}

func TestDeliveryRunRecoversFromTransientFetchFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		batchErr bool
	}{
		{name: "fetch request"},
		{name: "fetch batch", batchErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, ctx := testService(t, &testWriter{})
			intent := testIntent(t, service, ctx)
			if err := service.Submit(ctx, intent); err != nil {
				t.Fatal(err)
			}
			consumer := &failingFetchConsumer{Consumer: service.consumer, err: jetstream.ErrServerShutdown, batchErr: test.batchErr}
			service.consumer = consumer
			runCtx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() { done <- service.Run(runCtx) }()
			defer cancel()
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			for {
				receipt, err := service.Status(ctx, intent.OperationID)
				if err == nil {
					if receipt.Status != "accepted" || consumer.calls.Load() < 2 {
						t.Fatalf("receipt=%+v fetches=%d", receipt, consumer.calls.Load())
					}
					return
				}
				if !errors.Is(err, ErrPending) {
					t.Fatal(err)
				}
				select {
				case runErr := <-done:
					t.Fatalf("delivery stopped after transient fetch error: %v", runErr)
				case <-deadline.C:
					t.Fatal("delivery did not resume the durable intent")
				case <-time.After(20 * time.Millisecond):
				}
			}
		})
	}
}

// A consumer failure that is not a transport blip must stay local to the
// delivery worker: Run recreates its consumer instead of returning, which
// would stop the controller and its embedded broker.
func TestDeliveryRunRecreatesConsumerAfterPermanentFetchFailure(t *testing.T) {
	for _, permanent := range []error{jetstream.ErrInvalidOption, jetstream.ErrJetStreamNotEnabled,
		jetstream.ErrJetStreamNotEnabledForAccount, jetstream.ErrConsumerDeleted,
		nats.ErrPermissionViolation} {
		t.Run(permanent.Error(), func(t *testing.T) {
			service, ctx := testService(t, &testWriter{})
			intent := testIntent(t, service, ctx)
			if err := service.Submit(ctx, intent); err != nil {
				t.Fatal(err)
			}
			broken := &failingFetchConsumer{Consumer: service.consumer, err: permanent, failAlways: true}
			service.consumer = broken
			// Per service: another test's worker may still read the default.
			service.recovery = consumerRecovery{10 * time.Millisecond, 20 * time.Millisecond}
			runCtx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() { done <- service.Run(runCtx) }()
			defer cancel()
			deadline := time.After(5 * time.Second)
			for {
				receipt, err := service.Status(ctx, intent.OperationID)
				if err == nil {
					if receipt.Status != "accepted" || broken.calls.Load() == 0 {
						t.Fatalf("receipt=%+v broken fetches=%d", receipt, broken.calls.Load())
					}
					break
				}
				select {
				case runErr := <-done:
					t.Fatalf("delivery worker stopped on a consumer failure: %v", runErr)
				case <-deadline:
					t.Fatal("delivery did not recover its consumer")
				case <-time.After(20 * time.Millisecond):
				}
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run returned %v on cancellation", err)
			}
		})
	}
}

func TestPlannerRefusedIntentIsHeldAfterBoundedDeliveries(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	intent := testIntent(t, service, ctx)
	service.config.MaxPlannerAttempts = 3
	service.config.Planner = diagnosticPlanner{err: fmt.Errorf("no profile: %w", placement.ErrInvalidWorkload)}
	wire := mustJSON(intent)
	for delivered := uint64(1); delivered < 3; delivered++ {
		if terminal, err := service.processDelivery(ctx, wire, delivered); terminal || err == nil {
			t.Fatalf("delivery %d ended early: terminal=%t err=%v", delivered, terminal, err)
		}
	}
	if terminal, err := service.processDelivery(ctx, wire, 3); !terminal || err != nil {
		t.Fatalf("bounded delivery was not held: terminal=%t err=%v", terminal, err)
	}
	receipt, err := service.Status(ctx, intent.OperationID)
	if err != nil || receipt.Status != "held" || !strings.Contains(receipt.Error, "invalid_workload") {
		t.Fatalf("held receipt=%+v err=%v", receipt, err)
	}
	if terminal, err := service.processDelivery(ctx, wire, 4); !terminal || err != nil {
		t.Fatalf("redelivery after the held receipt was not a replay: %t %v", terminal, err)
	}

	transient, ctx := testService(t, &testWriter{})
	other := testIntent(t, transient, ctx)
	transient.config.MaxPlannerAttempts = 1
	transient.config.Planner = diagnosticPlanner{err: fmt.Errorf("read: %w", nats.ErrTimeout)}
	if terminal, err := transient.processDelivery(ctx, mustJSON(other), 50); terminal || err == nil {
		t.Fatalf("a transport failure counted toward the planner bound: %t %v", terminal, err)
	}

	// Redeliveries caused by leadership naks or transport errors raise the
	// broker delivery count; a first planner refusal after them is not held.
	inflated, ctx := testService(t, &testWriter{})
	late := testIntent(t, inflated, ctx)
	inflated.config.MaxPlannerAttempts = 3
	inflated.config.Planner = diagnosticPlanner{err: fmt.Errorf("no profile: %w", placement.ErrInvalidWorkload)}
	if terminal, err := inflated.processDelivery(ctx, mustJSON(late), 40); terminal || err == nil {
		t.Fatalf("a first refusal after inflated redeliveries was held: %t %v", terminal, err)
	}
}

func TestDeliveryRunSurvivesLostAckAfterDurableResult(t *testing.T) {
	writer := &testWriter{}
	service, ctx := testService(t, writer)
	intent := testIntent(t, service, ctx)
	if err := service.Submit(ctx, intent); err != nil {
		t.Fatal(err)
	}
	ackFailed := make(chan struct{})
	service.consumer = &failingAckConsumer{Consumer: service.consumer, ackErr: ackFailed}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- service.Run(runCtx) }()
	defer cancel()
	select {
	case <-ackFailed:
	case runErr := <-done:
		t.Fatalf("delivery stopped before acknowledgement: %v", runErr)
	case <-time.After(5 * time.Second):
		t.Fatal("intent was not processed")
	}
	receipt, err := service.Status(ctx, intent.OperationID)
	if err != nil || receipt.Status != "accepted" || writer.count() != 1 {
		t.Fatalf("durable receipt=%+v err=%v desired writes=%d", receipt, err, writer.count())
	}
	select {
	case runErr := <-done:
		t.Fatalf("delivery stopped after transient acknowledgement error: %v", runErr)
	case <-time.After(400 * time.Millisecond):
	}
}

func TestStandbyLeavesDurableIntentForNewLeader(t *testing.T) {
	w := &testWriter{}
	s, ctx := testService(t, w)
	fence := &testStandbyFence{}
	s.config.Fencer = fence
	i := testIntent(t, s, ctx)
	if err := s.Submit(ctx, i); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	time.Sleep(350 * time.Millisecond)
	if r, err := s.StatusFor(ctx, i); !errors.Is(err, ErrPending) || w.count() != 0 {
		t.Fatalf("standby processed intent: receipt=%+v err=%v calls=%d", r, err, w.count())
	}
	fence.leader.Store(true)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		r, err := s.StatusFor(ctx, i)
		if err == nil {
			if r.Status != "accepted" || w.count() != 1 {
				t.Fatalf("leader receipt=%+v calls=%d", r, w.count())
			}
			return
		}
		if !errors.Is(err, ErrPending) {
			t.Fatal(err)
		}
		select {
		case <-deadline.C:
			t.Fatal("new leader did not accept standby intent")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestStrictIntentRejectsDuplicateAndUnknownFields(t *testing.T) {
	for _, body := range []string{`{"schemaVersion":1,"schemaVersion":1}`, `{"unknown":1}`, `{"schemaVersion":1} {}`} {
		if _, err := DecodeIntent([]byte(body)); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}

func TestSignedUnadmittedIntentHasQueryVisibleRejection(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	i := Intent{SchemaVersion: SchemaVersion, OperationID: "0000000000NQMHCVBYP1N8ZHTR", Source: ArtifactSource{Repository: "https://github.com/TerraScale/ts-orchestrator", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TreeDigest: hex.EncodeToString(sha256.New().Sum(nil))}, ArtifactDigest: hex.EncodeToString(sha256.New().Sum(nil)), ManifestDigest: hex.EncodeToString(sha256.New().Sum(nil)), Cell: "lab", Role: "worker", Environment: "production", Generation: 1, DesiredReplicas: 1, ConfigDigest: ConfigDigestOf(nil, nil, nil), AuthorityEpoch: 1}
	if err := s.Submit(ctx, i); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		r, err := s.Status(ctx, i.OperationID)
		if err == nil {
			if r.Status != "rejected" || r.Error != "artifact is not admitted" {
				t.Fatalf("receipt=%+v", r)
			}
			return
		}
		if !errors.Is(err, ErrPending) {
			t.Fatal(err)
		}
		select {
		case <-deadline.C:
			t.Fatal("rejection never became query visible")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestConsumerAdmissionDecisionIgnoresStaleFollower(t *testing.T) {
	for _, scenario := range []string{"missing", "mismatched claim"} {
		t.Run(scenario, func(t *testing.T) {
			writer := &testWriter{}
			service, ctx := testService(t, writer)
			intent := testIntent(t, service, ctx)
			key := admissionKey(intent.ArtifactDigest, intent.Cell, intent.Role, intent.Environment)
			var staleEntry jetstream.KeyValueEntry
			var staleErr error
			if scenario == "missing" {
				staleErr = jetstream.ErrKeyNotFound
			} else {
				current, err := service.admissions.Get(ctx, key)
				if err != nil {
					t.Fatal(err)
				}
				var signed signedAdmission
				if err := json.Unmarshal(current.Value(), &signed); err != nil {
					t.Fatal(err)
				}
				signed.Record.Source.Commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
				signed.Record.ManifestDigest, err = signed.Record.calculatedManifestDigest()
				if err != nil {
					t.Fatal(err)
				}
				signed.Envelope, err = service.config.ArtifactSigner.SignArtifact(ctx, signed.Record)
				if err != nil {
					t.Fatal(err)
				}
				staleValue, err := json.Marshal(signed)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := service.admissions.Put(ctx, key, staleValue); err != nil {
					t.Fatal(err)
				}
				staleEntry, err = service.admissions.Get(ctx, key)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := service.admissions.Put(ctx, key, current.Value()); err != nil {
					t.Fatal(err)
				}
			}
			service.admissions = overriddenAdmissionGet{KeyValue: service.admissions, get: func(context.Context, string) (jetstream.KeyValueEntry, error) {
				return staleEntry, staleErr
			}}
			terminal, err := service.process(ctx, mustJSON(intent))
			if !terminal || err != nil {
				t.Fatalf("processing with stale follower admission: terminal=%t err=%v", terminal, err)
			}
			receipt, err := service.StatusFor(ctx, intent)
			if err != nil || receipt.Status != "accepted" || writer.count() != 1 {
				t.Fatalf("leader admission receipt=%+v err=%v desired writes=%d", receipt, err, writer.count())
			}
		})
	}
}

func TestConsumerAuthoritativeAdmissionAbsenceRejects(t *testing.T) {
	for _, scenario := range []string{"missing", "deleted"} {
		t.Run(scenario, func(t *testing.T) {
			writer := &testWriter{}
			service, ctx := testService(t, writer)
			intent := testIntent(t, service, ctx)
			if scenario == "missing" {
				intent.Role = "unadmitted"
			} else {
				key := admissionKey(intent.ArtifactDigest, intent.Cell, intent.Role, intent.Environment)
				staleEntry, err := service.admissions.Get(ctx, key)
				if err != nil {
					t.Fatal(err)
				}
				if err := service.admissions.Delete(ctx, key); err != nil {
					t.Fatal(err)
				}
				service.admissions = overriddenAdmissionGet{KeyValue: service.admissions, get: func(context.Context, string) (jetstream.KeyValueEntry, error) {
					return staleEntry, nil
				}}
			}
			terminal, err := service.process(ctx, mustJSON(intent))
			if !terminal || err != nil {
				t.Fatalf("processing without authoritative admission: terminal=%t err=%v", terminal, err)
			}
			receipt, err := service.StatusFor(ctx, intent)
			if err != nil || receipt.Status != "rejected" || receipt.Error != "artifact is not admitted" || writer.count() != 0 {
				t.Fatalf("absent admission receipt=%+v err=%v desired writes=%d", receipt, err, writer.count())
			}
		})
	}
}

func TestCancellationAfterHostEffectReplaysBeforeAck(t *testing.T) {
	w := &testWriter{cancelFirst: true}
	s, ctx := testService(t, w)
	i := testIntent(t, s, ctx)
	b := mustJSON(i)
	terminal, err := s.process(ctx, b)
	if terminal || !errors.Is(err, context.Canceled) {
		t.Fatalf("first process terminal=%t err=%v", terminal, err)
	}
	if _, err := s.Status(ctx, i.OperationID); !errors.Is(err, ErrPending) {
		t.Fatalf("premature receipt: %v", err)
	}
	terminal, err = s.process(ctx, b)
	if !terminal || err != nil {
		t.Fatalf("redelivery terminal=%t err=%v", terminal, err)
	}
	r, err := s.Status(ctx, i.OperationID)
	if err != nil || r.Status != "accepted" || w.count() != 2 {
		t.Fatalf("receipt=%+v err=%v calls=%d", r, err, w.count())
	}
}

func TestFencedClaimIsHeldDurably(t *testing.T) {
	w := &testWriter{fenceFirst: true}
	s, ctx := testService(t, w)
	i := testIntent(t, s, ctx)
	terminal, err := s.process(ctx, mustJSON(i))
	if !terminal || err != nil {
		t.Fatalf("fenced process terminal=%t err=%v", terminal, err)
	}
	r, err := s.StatusFor(ctx, i)
	if err != nil || r.Status != "held" || w.count() != 1 {
		t.Fatalf("held receipt=%+v err=%v calls=%d", r, err, w.count())
	}
	terminal, err = s.process(ctx, mustJSON(i))
	if !terminal || err != nil || w.count() != 1 {
		t.Fatalf("held replay terminal=%t err=%v calls=%d", terminal, err, w.count())
	}
}

func TestCommittedDesiredConflictIsHeldDurably(t *testing.T) {
	w := &testWriter{conflictFirst: true}
	s, ctx := testService(t, w)
	i := testIntent(t, s, ctx)
	terminal, err := s.process(ctx, mustJSON(i))
	if !terminal || err != nil {
		t.Fatalf("conflicted process terminal=%t err=%v", terminal, err)
	}
	r, err := s.StatusFor(ctx, i)
	if err != nil || r.Status != "held" || w.count() != 1 {
		t.Fatalf("held receipt=%+v err=%v calls=%d", r, err, w.count())
	}
	terminal, err = s.process(ctx, mustJSON(i))
	if !terminal || err != nil || w.count() != 1 {
		t.Fatalf("held replay terminal=%t err=%v calls=%d", terminal, err, w.count())
	}
}

func TestSignedIntentRedeliveryAfterExpiryUsesDurableAdmission(t *testing.T) {
	w := &testWriter{failFirst: true}
	s, ctx := testService(t, w)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 24, 9, 0, 0, 0, time.UTC)
	codec := Ed25519Codec{Cell: "lab", Actor: "operator", PrivateKey: priv, Trusted: map[string]TrustedSigner{keyID: {Actor: "operator", PublicKey: pub}}, Lifetime: time.Minute, MaxLifetime: time.Minute, Now: func() time.Time { return now }}
	s.config.Signer = codec
	s.config.Verifier = codec
	s.config.ArtifactSigner = codec
	s.config.ArtifactVerifier = codec
	i := testIntent(t, s, ctx)
	wire, err := codec.Sign(ctx, mustJSON(i))
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := s.process(ctx, wire)
	if terminal || err == nil {
		t.Fatalf("first attempt terminal=%t err=%v", terminal, err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := codec.Verify(ctx, wire); !errors.Is(err, protocol.ErrExpired) {
		t.Fatalf("wire should be expired: %v", err)
	}
	terminal, err = s.process(ctx, wire)
	if !terminal || err != nil {
		t.Fatalf("redelivery terminal=%t err=%v", terminal, err)
	}
	r, err := s.Status(ctx, i.OperationID)
	if err != nil || r.Status != "accepted" || w.count() != 2 {
		t.Fatalf("receipt=%+v err=%v calls=%d", r, err, w.count())
	}
	if _, err := s.readAdmission(ctx, i.ArtifactDigest, i.Cell, i.Role, i.Environment); err != nil {
		t.Fatalf("archived signed artifact claim: %v", err)
	}
}

// A redelivered intent resumes from its durable verified record but is
// authorized again: a signer or grant revoked since the first delivery stops
// it, and a codec's Lookup finds signers as they are now.
func TestSignedIntentRedeliveryIsAuthorizedAgain(t *testing.T) {
	w := &testWriter{failFirst: true}
	s, ctx := testService(t, w)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	var trusted atomic.Bool
	trusted.Store(true)
	codec := Ed25519Codec{Cell: "lab", Actor: "operator", PrivateKey: priv, Lifetime: time.Minute, MaxLifetime: time.Minute,
		Lookup: func(id string) (TrustedSigner, bool) {
			return TrustedSigner{Actor: "operator", PublicKey: pub}, id == keyID && trusted.Load()
		}}
	s.config.Signer, s.config.Verifier, s.config.ArtifactSigner, s.config.ArtifactVerifier = codec, codec, codec, codec
	var revoked atomic.Bool
	authorize := s.config.Authorize
	s.config.Authorize = func(ctx context.Context, actor string, intent Intent) error {
		if revoked.Load() {
			return ErrUnauthorized
		}
		return authorize(ctx, actor, intent)
	}
	i := testIntent(t, s, ctx)
	wire, err := codec.Sign(ctx, mustJSON(i))
	if err != nil {
		t.Fatal(err)
	}
	if terminal, err := s.process(ctx, wire); terminal || err == nil {
		t.Fatalf("first attempt terminal=%t err=%v", terminal, err)
	}
	revoked.Store(true)
	if terminal, err := s.process(ctx, wire); !terminal || err != nil || w.count() != 1 {
		t.Fatalf("redelivery after the grant was revoked: terminal=%t err=%v, %d writes", terminal, err, w.count())
	}
	if r, err := s.Status(ctx, i.OperationID); err == nil && r.Status == "accepted" {
		t.Fatalf("a revoked actor's redelivered intent was accepted: %+v", r)
	}
	trusted.Store(false)
	if _, err := codec.Verify(ctx, wire); err == nil {
		t.Fatal("a codec verified with a signer its Lookup no longer finds")
	}
}

func TestPreConsumerConflictingPublishCannotImpersonateReceipt(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	first := testIntent(t, s, ctx)
	second := first
	second.Generation++
	if err := s.Submit(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.Submit(ctx, second); err != nil {
		t.Fatalf("content-bound publish: %v", err)
	}
	stream, err := s.js.Stream(ctx, IntentStream)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 2 {
		t.Fatalf("conflicting payload was deduplicated: %d messages", info.State.Msgs)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		r, err := s.StatusFor(ctx, first)
		if err == nil {
			if r.Status != "accepted" {
				t.Fatalf("first status %+v", r)
			}
			break
		}
		if !errors.Is(err, ErrPending) {
			t.Fatal(err)
		}
		select {
		case <-deadline.C:
			t.Fatal("first intent not accepted")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if _, err := s.StatusFor(ctx, second); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting status: %v", err)
	}
}

func TestRealHostDesiredCallerRejectsEpochHandoff(t *testing.T) {
	s, r, ctx := testServiceWithRuntime(t, &testWriter{})
	control, err := authority.Start(ctx, r.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "lab", CandidateID: "0000000000A8ZV3QT0H276P43A", Replicas: 1, RenewInterval: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() || control.Current().Epoch != 1 {
		t.Fatalf("authority not acquired: %+v", control.Current())
	}
	_, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch := atomic.Uint64{}
	epoch.Store(1)
	guardCalls := atomic.Int32{}
	armed := atomic.Bool{}
	controller, err := host.NewController(ctx, host.ControllerConfig{Cell: "lab", Conn: r.Conn(), JS: r.JetStream(), Artifacts: s.Artifacts(), ResponseKey: responseKey, StateReplicas: 1, HostMutations: control, AuthorityEpoch: epoch.Load, AuthorityGuard: func(guardCtx context.Context, expected uint64) error {
		if armed.Load() && guardCalls.Add(1) == 2 {
			epoch.Store(2)
		}
		if epoch.Load() != expected {
			return authority.ErrFenced
		}
		return control.Guard(guardCtx, expected)
	}})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	userPublic, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = controller.Register(ctx, host.Registration{Cell: "lab", Node: "node-one", Environment: "production", Roles: []string{"worker"}, PublicKey: base64.StdEncoding.EncodeToString(pub), NATSUserPublicKey: userPublic, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	s.config.Writer = controller
	i := testIntent(t, s, ctx)
	if terminal, err := s.process(ctx, mustJSON(i)); !terminal || err != nil {
		t.Fatalf("real host desired terminal=%t err=%v", terminal, err)
	}
	e, err := control.ReadHostMutation(ctx, authority.MutationDesired, "lab.node-one.worker")
	if err != nil {
		t.Fatal(err)
	}
	var desired host.Desired
	if err := json.Unmarshal(e.Payload, &desired); err != nil {
		t.Fatal(err)
	}
	if desired.Digest != i.ArtifactDigest || desired.Generation != 1 {
		t.Fatalf("host desired=%+v", desired)
	}
	other := i
	other.OperationID = "0000000000FJWGFCWW9Q05ET6C"
	other.Generation = 2
	guardCalls.Store(0)
	armed.Store(true)
	if terminal, err := s.process(ctx, mustJSON(other)); !terminal || err != nil {
		t.Fatalf("fenced host desired terminal=%t err=%v", terminal, err)
	}
	if receipt, err := s.StatusFor(ctx, other); err != nil || receipt.Status != "held" {
		t.Fatalf("fenced operation receipt: %+v %v", receipt, err)
	}
	e, err = control.ReadHostMutation(ctx, authority.MutationDesired, "lab.node-one.worker")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(e.Payload, &desired); err != nil {
		t.Fatal(err)
	}
	if desired.Generation != 1 {
		t.Fatalf("stale leader wrote desired generation %d", desired.Generation)
	}
}

func mustJSON(i Intent) []byte {
	b, err := json.Marshal(i)
	if err != nil {
		panic(fmt.Sprintf("marshal test intent: %v", err))
	}
	return b
}
