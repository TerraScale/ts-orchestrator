package delivery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"github.com/nats-io/nats.go"

	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"

	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"

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
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
}

func (testFence) Guard(_ context.Context, epoch uint64) error {
	if epoch != 1 {
		return errors.New("fenced")
	}
	return nil
}

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

func mustJSON(i Intent) []byte {
	b, err := json.Marshal(i)
	if err != nil {
		panic(fmt.Sprintf("marshal test intent: %v", err))
	}
	return b
}
