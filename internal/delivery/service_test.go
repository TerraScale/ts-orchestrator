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
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type testCodec struct{}

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
	return authority.Snapshot{Ready: true, Leader: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
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
	err      error
	batchErr bool
	calls    atomic.Int32
}

func (c *failingFetchConsumer) Fetch(batch int, opts ...jetstream.FetchOpt) (jetstream.MessageBatch, error) {
	if c.calls.Add(1) == 1 {
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
	return authority.Snapshot{Ready: f.leader.Load(), Leader: f.leader.Load(), Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
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

func testServiceWithRuntime(t *testing.T, writer *testWriter) (*Service, *natscell.Runtime, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	r, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "one", Replicas: 1, Lab: true, Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	s, err := Open(ctx, Config{JS: r.JetStream(), Cell: "lab", Replicas: 1, Signer: testCodec{}, Verifier: testCodec{}, ArtifactSigner: testCodec{}, ArtifactVerifier: testCodec{}, AuthorizeArtifact: func(context.Context, string, ArtifactRecord) error { return nil }, Authorize: func(context.Context, string, Intent) error { return nil }, Fencer: testFence{}, Planner: testPlanner{}, Writer: writer})
	if err != nil {
		t.Fatal(err)
	}
	return s, r, ctx
}

func testIntent(t *testing.T, s *Service, ctx context.Context) Intent {
	t.Helper()
	source := ArtifactSource{Repository: "https://git.terrascale.tech/TerraScale/ts-orchestrator", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TreeDigest: hex.EncodeToString(sha256.New().Sum(nil))}
	request := ArtifactClaimRequest{Source: source, Cell: "lab", Role: "worker", Environment: "production"}
	artifact, wire, err := s.PrepareArtifact(ctx, bytes.NewReader([]byte("#!/bin/sh\necho ready\n")), request)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err = s.AcceptArtifactClaim(ctx, wire)
	if err != nil {
		t.Fatal(err)
	}
	return Intent{SchemaVersion: SchemaVersion, OperationID: "deploy-one", Source: source, ArtifactDigest: artifact.Digest, ManifestDigest: artifact.ManifestDigest, Cell: "lab", Role: "worker", Environment: "production", Generation: 1, DesiredReplicas: 1, ConfigDigest: ConfigDigestOf(nil, nil), AuthorityEpoch: 1}
}

func TestArtifactAdmissionBindsSourceAndReadback(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	client, err := ConnectClient(ctx, Config{JS: s.js, Cell: "lab", ArtifactSigner: testCodec{}, ArtifactVerifier: testCodec{}, AuthorizeArtifact: func(context.Context, string, ArtifactRecord) error { return nil }})
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
	source := ArtifactSource{Repository: "https://git.terrascale.tech/TerraScale/ts-orchestrator", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TreeDigest: hex.EncodeToString(sha256.New().Sum(nil))}
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

func TestDeliveryRunRejectsPermanentFetchFailure(t *testing.T) {
	for _, permanent := range []error{jetstream.ErrInvalidOption, jetstream.ErrJetStreamNotEnabled,
		jetstream.ErrJetStreamNotEnabledForAccount, jetstream.ErrConsumerDeleted,
		nats.ErrPermissionViolation} {
		t.Run(permanent.Error(), func(t *testing.T) {
			service, ctx := testService(t, &testWriter{})
			service.consumer = &failingFetchConsumer{Consumer: service.consumer, err: permanent}
			if err := service.Run(ctx); !errors.Is(err, permanent) {
				t.Fatalf("permanent consumer error was retried or hidden: %v", err)
			}
		})
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
	i := Intent{SchemaVersion: SchemaVersion, OperationID: "unadmitted-one", Source: ArtifactSource{Repository: "https://git.terrascale.tech/TerraScale/ts-orchestrator", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TreeDigest: hex.EncodeToString(sha256.New().Sum(nil))}, ArtifactDigest: hex.EncodeToString(sha256.New().Sum(nil)), ManifestDigest: hex.EncodeToString(sha256.New().Sum(nil)), Cell: "lab", Role: "worker", Environment: "production", Generation: 1, DesiredReplicas: 1, ConfigDigest: ConfigDigestOf(nil, nil), AuthorityEpoch: 1}
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
	control, err := authority.Start(ctx, r.JetStream(), authority.Config{Scope: "lab", CandidateID: "delivery-test", Replicas: 1, RenewInterval: 3 * time.Second})
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
	_, err = controller.Register(ctx, host.Registration{Cell: "lab", Node: "node-one", Environment: "production", Roles: []string{"worker"}, PublicKey: base64.StdEncoding.EncodeToString(pub), Generation: 1})
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
	other.OperationID = "deploy-two"
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
