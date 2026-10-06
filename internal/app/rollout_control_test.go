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

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

type rolloutTestFence struct{ epoch uint64 }

func (f rolloutTestFence) Current() authority.Snapshot {
	return authority.Snapshot{Ready: true, Leader: true, Epoch: f.epoch, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
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

func newRolloutRequester(t *testing.T) *rolloutRequester {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
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
	fence := rolloutTestFence{epoch: 7}
	store, err := rollout.OpenStore(t.Context(), js, "gru", 1, fence)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, reader, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}, Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{{
		Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(public), Roles: []string{"terrabase"},
		Environments: []string{"canary"}, CanRollOutOrchestrator: true}, {
		Actor: "ci", PublicKey: base64.StdEncoding.EncodeToString(reader.Public().(ed25519.PublicKey)),
		Roles: []string{"terrabase"}, Environments: []string{"canary"}}}}}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	control, err := newRolloutControl(cfg, nil)
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
	scope := protocol.EnvelopeScope{Region: "gru", Kind: kind, Actor: "ops", OperationID: "rollout.test",
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

func TestRolloutRequestsPublishPauseAndRollBack(t *testing.T) {
	r := newRolloutRequester(t)
	first, second := strings.Repeat("a", 64), strings.Repeat("b", 64)
	reply, err := r.serve(r.sign(rolloutPublishKind, rolloutPublishRequest{Receipt: []byte("receipt:" + first)}, nil))
	if err != nil || reply.Status != "published" || reply.Desired == nil || reply.Desired.Generation != 1 ||
		reply.Desired.Actor != "ops" || reply.Desired.Receipt != nil || reply.Desired.RunNumber != 9 ||
		reply.Desired.SourceRevision != strings.Repeat("e", 40) {
		t.Fatalf("publish = %+v %v", reply, err)
	}
	if reply, err := r.serve(r.sign(rolloutPublishKind, rolloutPublishRequest{Receipt: []byte("receipt:" + first)}, nil)); err != nil || reply.Status != "unchanged" {
		t.Fatalf("republish = %+v %v", reply, err)
	}
	if _, err := r.serve(r.sign(rolloutPublishKind, rolloutPublishRequest{Receipt: []byte("receipt:" + second)}, nil)); err != nil {
		t.Fatal(err)
	}
	if reply, err := r.serve(r.sign(rolloutPauseKind, struct{}{}, nil)); err != nil || reply.Status != "paused" || !reply.Paused {
		t.Fatalf("pause = %+v %v", reply, err)
	}
	reply, err = r.serve(r.sign(rolloutRollbackKind, rolloutRollbackRequest{To: 1}, nil))
	if err != nil || reply.Status != "rolled-back" || reply.Desired.Generation != 3 || reply.Desired.RollbackOf != 1 ||
		reply.Desired.Digest != first || reply.Desired.RunNumber != 9 || !reply.Paused || len(reply.History) != 3 {
		t.Fatalf("rollback = %+v %v", reply, err)
	}
	if reply, err := r.serve(r.sign(rolloutResumeKind, struct{}{}, nil)); err != nil || reply.Status != "resumed" || reply.Paused {
		t.Fatalf("resume = %+v %v", reply, err)
	}
	if reply, err := r.serve(r.sign(rolloutStatusKind, struct{}{}, nil)); err != nil || reply.Status != "" || reply.Desired.Generation != 3 {
		t.Fatalf("status = %+v %v", reply, err)
	}
}

func TestRolloutRequestsRefuseUntrustedStaleAndTamperedRequests(t *testing.T) {
	r := newRolloutRequester(t)
	digest := strings.Repeat("a", 64)
	publish := rolloutPublishRequest{Receipt: []byte("receipt:" + digest)}
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tampered := r.sign(rolloutPublishKind, publish, nil)
	tampered = []byte(strings.Replace(string(tampered), base64.StdEncoding.EncodeToString([]byte("receipt:"+digest)),
		base64.StdEncoding.EncodeToString([]byte("receipt:"+strings.Repeat("c", 64))), 1))
	foreign := *r
	foreign.key = stranger
	for name, test := range map[string]struct {
		wire []byte
		want string
	}{
		"unknown signer":  {foreign.sign(rolloutPublishKind, publish, nil), "untrusted"},
		"other actor":     {r.sign(rolloutPublishKind, publish, func(s *protocol.EnvelopeScope, _ *time.Time) { s.Actor = "ci" }), "untrusted"},
		"other cell":      {r.sign(rolloutPublishKind, publish, func(s *protocol.EnvelopeScope, _ *time.Time) { s.Region = "fra" }), ""},
		"expired":         {r.sign(rolloutPublishKind, publish, func(_ *protocol.EnvelopeScope, at *time.Time) { *at = at.Add(-2 * time.Minute) }), ""},
		"tampered":        {tampered, ""},
		"bad receipt":     {r.sign(rolloutPublishKind, rolloutPublishRequest{Receipt: []byte("forged")}, nil), "release receipt"},
		"unknown kind":    {r.sign("rollout.delete", struct{}{}, nil), "unknown rollout request"},
		"future rollback": {r.sign(rolloutRollbackKind, rolloutRollbackRequest{To: 4}, nil), "no such release generation"},
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
	for _, kind := range []string{rolloutPublishKind, rolloutPauseKind, rolloutResumeKind, rolloutRollbackKind} {
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
	if _, err := r.serve(r.sign(rolloutPublishKind, rolloutPublishRequest{Receipt: []byte("receipt:" + strings.Repeat("b", 64))}, nil)); err != nil {
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
	if _, err := r.serve(r.sign(rolloutStatusKind, struct{}{}, nil)); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("status without a store: %v", err)
	}
}

func TestRolloutConfigAndCommandFlagsAreChecked(t *testing.T) {
	if _, err := newRolloutControl(Config{Controller: ControllerConfig{Rollouts: &RolloutsConfig{Executor: true}}}, nil); err == nil {
		t.Fatal("an executor without the rollout store was accepted")
	}
	production := Config{Controller: ControllerConfig{Rollouts: &RolloutsConfig{Enabled: true, Executor: true}}}
	if _, err := newRolloutControl(production, nil); err == nil || !strings.Contains(err.Error(), "step agent") {
		t.Fatalf("a production executor without step agents: %v", err)
	}
	policy := rollout.DefaultPolicy()
	policy.CanaryUnits = 0
	if _, err := newRolloutControl(Config{Controller: ControllerConfig{Rollouts: &RolloutsConfig{Enabled: true, Policy: &policy}}}, nil); err == nil {
		t.Fatal("a policy without a canary was accepted")
	}
	for _, test := range []struct {
		command, receipt string
		to               uint64
	}{{"publish", "", 0}, {"rollback", "", 0}, {"status", "", 3}, {"pause", "receipt.json", 0}, {"rollback", "receipt.json", 2}} {
		if _, err := rolloutPayload(test.command, test.receipt, "", test.to); err == nil {
			t.Fatalf("rollout %s accepted --receipt %q --to %d", test.command, test.receipt, test.to)
		}
	}
	if payload, err := rolloutPayload("rollback", "", "", 2); err != nil || payload.(rolloutRollbackRequest).To != 2 {
		t.Fatalf("rollback payload = %v %v", payload, err)
	}
}
