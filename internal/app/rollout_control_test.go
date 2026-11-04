package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
)

type rolloutTestFence struct{ epoch uint64 }

func (f rolloutTestFence) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: f.epoch, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
}

func (f rolloutTestFence) Guard(_ context.Context, epoch uint64) error {
	if epoch != f.epoch {
		return authority.ErrFenced
	}
	return nil
}

type rolloutRequester struct {
	t       *testing.T
	control *rolloutControl
	policy  signerPolicy
	fence   rolloutTestFence
	key     ed25519.PrivateKey
	// reader is a trusted signer without can_roll_out_orchestrator.
	reader ed25519.PrivateKey
}

// testRolloutStore opens a rollout store for cell gru on a fresh broker.
func testRolloutStore(t *testing.T, fence authority.Fencer) *rollout.Store {
	t.Helper()
	store, err := rollout.OpenStore(t.Context(), testRolloutJetStream(t), "gru", 1, fence)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// testRolloutJetStream starts a fresh single broker.
func testRolloutJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	auth := newAuthenticatedNATS(t, "gru")
	runtime, err := auth.start(t, t.Context(), natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{}})
	if err != nil {
		t.Fatal(err)
	}
	return runtime.JetStream()
}

func newRolloutRequester(t *testing.T) *rolloutRequester {
	t.Helper()
	fence := rolloutTestFence{epoch: 7}
	store := testRolloutStore(t, fence)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, reader, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{NATS: natscell.Config{Cell: "gru"}, Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{{
		Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(public), Roles: []string{"terrabase"},
		Environments: []string{"canary"}, CanRollOutOrchestrator: true}, {
		Actor: "ci", PublicKey: base64.StdEncoding.EncodeToString(reader.Public().(ed25519.PublicKey)),
		Roles: []string{"terrabase"}, Environments: []string{"canary"}}}}}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	control, err := newRolloutControl(cfg, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	control.verify = testReceiptDigest
	control.store.Store(store)
	return &rolloutRequester{t: t, control: control, policy: policy, fence: fence, key: private, reader: reader}
}

// sign returns a signed request; edit changes the scope before signing.
func (r *rolloutRequester) sign(kind string, payload any, edit func(*protocol.EnvelopeScope, *time.Time)) []byte {
	r.t.Helper()
	encoded, err := protocol.EncodeJSON(payload)
	if err != nil {
		r.t.Fatal(err)
	}
	scope := protocol.EnvelopeScope{Region: "gru", Kind: kind, Actor: "ops", OperationID: "0000000000EDWEB4XTSZSDFWS4",
		Generation: 1, Epoch: 7}
	issued := time.Now().UTC()
	if edit != nil {
		edit(&scope, &issued)
	}
	envelope, err := protocol.SignEnvelope(encoded, scope, issued, issued.Add(time.Minute), r.key)
	if err != nil {
		r.t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		r.t.Fatal(err)
	}
	return wire
}

func (r *rolloutRequester) serve(wire []byte) (rolloutReply, error) {
	return r.control.serve(r.t.Context(), wire, r.policy, r.fence)
}

func TestRolloutRequestsRefuseUntrustedStaleAndTamperedRequests(t *testing.T) {
	r := newRolloutRequester(t)
	digest := strings.Repeat("a", 64)
	publish := rolloutPublishRequest{Receipt: []byte("receipt:9:" + digest)}
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign := *r
	foreign.key = stranger
	for name, test := range map[string]struct {
		wire []byte
		want string
	}{
		"unknown signer": {foreign.sign(rolloutPublishKind, publish, nil), "untrusted"},
	} {
		if _, err := r.serve(test.wire); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := r.serve(r.sign(rolloutPublishKind, publish, func(s *protocol.EnvelopeScope, _ *time.Time) { s.Epoch = 6 })); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("stale epoch: %v", err)
	}
	if desired, _, err := r.control.store.Load().Desired(t.Context()); err != nil || desired.Generation() != 0 {
		t.Fatalf("a refused request moved the cell: %+v %v", desired, err)
	}

	// A trusted signer without the rollout grant may only read the status.
	reader := *r
	reader.key = r.reader
	for _, kind := range []string{rolloutPublishKind} {
		wire := reader.sign(kind, publish, func(s *protocol.EnvelopeScope, _ *time.Time) { s.Actor = "ci" })
		if _, err := r.serve(wire); err == nil || !strings.Contains(err.Error(), "can_roll_out_orchestrator") {
			t.Fatalf("%s without the rollout grant: %v", kind, err)
		}
	}
	if _, err := r.serve(reader.sign(rolloutStatusKind, struct{}{}, func(s *protocol.EnvelopeScope, _ *time.Time) { s.Actor = "ci" })); err != nil {
		t.Fatalf("status without the rollout grant: %v", err)
	}

	// A rollback to a generation whose receipt no longer verifies is
	// refused before the cell moves.
	if _, err := r.serve(r.sign(rolloutPublishKind, publish, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.serve(r.sign(rolloutPublishKind, rolloutPublishRequest{Receipt: []byte("receipt:10:" + strings.Repeat("b", 64))}, nil)); err != nil {
		t.Fatal(err)
	}
	r.control.verify = func(receipt, _ []byte, _ time.Time) (rollout.Release, error) {
		if strings.HasSuffix(string(receipt), digest) {
			return rollout.Release{}, errors.New("delegation expired")
		}
		return testReceiptDigest(receipt, nil, time.Time{})
	}
	if _, err := r.serve(r.sign(rolloutRollbackKind, rolloutRollbackRequest{To: 1}, nil)); err == nil || !strings.Contains(err.Error(), "no longer verifies") {
		t.Fatalf("rollback to an expired receipt: %v", err)
	}
	if desired, _, err := r.control.store.Load().Desired(t.Context()); err != nil || desired.Generation() != 2 {
		t.Fatalf("a refused rollback moved the cell: %+v %v", desired, err)
	}

	// Without release roots nothing is published; without the store
	// nothing is answered.
	r.control.verify = nil
	if _, err := r.serve(r.sign(rolloutPublishKind, publish, nil)); err == nil || !strings.Contains(err.Error(), "trust roots") {
		t.Fatalf("publish without roots: %v", err)
	}
	r.control.store.Store(nil)
	if _, err := r.serve(r.sign(rolloutStatusKind, struct{}{}, nil)); err == nil || !strings.Contains(err.Error(), "not open") {
		t.Fatalf("status without a store: %v", err)
	}
}
