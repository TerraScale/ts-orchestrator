package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type ingressDigestVerifier struct{}

func (ingressDigestVerifier) Verify(payload protocol.OpaquePayload, expected protocol.PayloadDigest) protocol.VerificationOutcome {
	digest := sha256.Sum256(payload.Bytes())
	if expected.Equal(func() protocol.PayloadDigest { value, _ := protocol.PayloadDigestTryCopyFrom(digest[:]); return value }()) {
		return protocol.VerificationOutcomeValid
	}
	return protocol.VerificationOutcomeInvalid
}

func TestNatsCommandIngressAdmitsOnceAndRejectsHostileReplay(t *testing.T) {
	connection := startIngressTestNATS(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := security.NewCommandSignatureVerifierFromKeys([]security.CommandSignatureTrustKey{{
		KeyID: signer.PublicKeyID(), Algorithm: security.CommandSignatureAlgorithm,
		PublicKeySPKI: mustIngressSPKI(t, &key.PublicKey),
	}})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := security.NewMemoryCommandReplayStore(16)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := security.NewCommandSecurityBoundary(verifier, replay, 0)
	if err != nil {
		t.Fatal(err)
	}
	cell, _ := contracts.CellIdTryCreate("sfo")
	aggregate, _ := contracts.AggregateIdTryCreate("runtime")
	generation, _ := protocol.DesiredGenerationTryCreate(1)
	epoch, _ := protocol.WriterEpochTryCreate(1)
	version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
	var dispatches atomic.Int32
	now := time.Now().UTC()
	ingress, err := NewNatsCommandIngress(NatsCommandIngressConfiguration{
		Connection: connection, Subject: "ts.orch.v1.sfo.command.runtime", Boundary: boundary,
		ExpectedCell: cell, ExpectedAggregateID: aggregate, MinimumDesiredGeneration: generation,
		MinimumWriterEpoch: epoch, AcceptedProtocolVersions: []protocol.ProtocolRevision{version},
		PayloadDigestVerifier: ingressDigestVerifier{}, Now: func() time.Time { return now },
		Dispatch: func(context.Context, protocol.CommandEnvelope) error { dispatches.Add(1); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ingress.Close() })

	envelope := ingressTestEnvelope(t, signer, cell, aggregate, now)
	wire, err := protocol.EncodeCommandEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := ingress.Handle(context.Background(), wire)
	if err != nil || decision.Code != CommandIngressCodeAccepted {
		t.Fatalf("valid command was not admitted: %v, %v", decision, err)
	}
	decision, err = ingress.Handle(context.Background(), wire)
	if err != nil || decision.SecurityOutcome != security.CommandSecurityReplayDetected {
		t.Fatalf("replay was not rejected: %v, %v", decision, err)
	}
	if dispatches.Load() != 1 {
		t.Fatalf("dispatch count = %d", dispatches.Load())
	}

	wrongCell, _ := contracts.CellIdTryCreate("iad")
	hostile := ingressTestEnvelope(t, signer, wrongCell, aggregate, now)
	hostileWire, _ := protocol.EncodeCommandEnvelope(hostile)
	decision, err = ingress.Handle(context.Background(), hostileWire)
	if err != nil || decision.Code != CommandIngressCodeRejected || decision.ValidationError != protocol.CommandValidationErrorWrongCell {
		t.Fatalf("tenant mismatch was not rejected before dispatch: %v, %v", decision, err)
	}
	if dispatches.Load() != 1 {
		t.Fatal("hostile command reached the dispatcher")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if decision, err := ingress.Handle(canceled, wire); err == nil || decision.Code != CommandIngressCodeCanceled {
		t.Fatalf("canceled command was not stopped: %v, %v", decision, err)
	}
	if err := ingress.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ingress.Handle(context.Background(), wire); err == nil {
		t.Fatal("closed command ingress accepted a direct payload")
	}
}

func TestNatsCommandIngressRejectsMemoryReplayForMultiInstance(t *testing.T) {
	connection := startIngressTestNATS(t)
	replay, err := security.NewMemoryCommandReplayStore(2)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := security.NewCommandSecurityBoundary(nil, replay, 0)
	if err == nil || boundary != nil {
		t.Fatal("nil verifier unexpectedly produced a security boundary")
	}
	// A prebuilt boundary is tested through a minimal verifier so the failure
	// is specifically the process-local replay policy, not identity loading.
	validVerifier := ingressAlwaysValidVerifier{}
	boundary, err = security.NewCommandSecurityBoundary(validVerifier, replay, 0)
	if err != nil {
		t.Fatal(err)
	}
	cell, _ := contracts.CellIdTryCreate("sfo")
	aggregate, _ := contracts.AggregateIdTryCreate("runtime")
	generation, _ := protocol.DesiredGenerationTryCreate(1)
	epoch, _ := protocol.WriterEpochTryCreate(1)
	version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
	if _, err := NewNatsCommandIngress(NatsCommandIngressConfiguration{
		Connection: connection, Subject: "ts.orch.v1.sfo.command.runtime", Boundary: boundary,
		Replay: replay, MultiInstance: true, ExpectedCell: cell, ExpectedAggregateID: aggregate,
		MinimumDesiredGeneration: generation, MinimumWriterEpoch: epoch,
		AcceptedProtocolVersions: []protocol.ProtocolRevision{version},
		PayloadDigestVerifier:    ingressDigestVerifier{}, Dispatch: func(context.Context, protocol.CommandEnvelope) error { return nil },
	}); err == nil {
		t.Fatal("multi-instance ingress accepted process-local replay")
	}
}

func TestNatsCommandIngressStartsAndStopsExactSubscription(t *testing.T) {
	connection := startIngressTestNATS(t)
	replay, err := security.NewMemoryCommandReplayStore(4)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := security.NewCommandSecurityBoundary(ingressAlwaysValidVerifier{}, replay, 0)
	if err != nil {
		t.Fatal(err)
	}
	cell, _ := contracts.CellIdTryCreate("sfo")
	aggregate, _ := contracts.AggregateIdTryCreate("runtime")
	generation, _ := protocol.DesiredGenerationTryCreate(1)
	epoch, _ := protocol.WriterEpochTryCreate(1)
	version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
	started := make(chan struct{}, 1)
	ingress, err := NewNatsCommandIngress(NatsCommandIngressConfiguration{
		Connection: connection, Subject: "ts.orch.v1.sfo.command.runtime", Boundary: boundary,
		ExpectedCell: cell, ExpectedAggregateID: aggregate, MinimumDesiredGeneration: generation,
		MinimumWriterEpoch: epoch, AcceptedProtocolVersions: []protocol.ProtocolRevision{version},
		PayloadDigestVerifier: ingressDigestVerifier{}, Dispatch: func(context.Context, protocol.CommandEnvelope) error {
			started <- struct{}{}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ingress.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ingress.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ingress.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ingress.Completion():
	case <-time.After(time.Second):
		t.Fatal("ingress completion did not close")
	}
	select {
	case <-started:
		t.Fatal("lifecycle test unexpectedly dispatched a command")
	default:
	}
}

type ingressAlwaysValidVerifier struct{}

func (ingressAlwaysValidVerifier) Verify(protocol.CommandSignedMaterial, protocol.OpaqueSignature) protocol.VerificationOutcome {
	return protocol.VerificationOutcomeValid
}

func ingressTestEnvelope(t *testing.T, signer *security.CommandSignatureSigner, cell contracts.CellId, aggregate contracts.AggregateId, now time.Time) protocol.CommandEnvelope {
	t.Helper()
	version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
	generation, _ := protocol.DesiredGenerationTryCreate(1)
	epoch, _ := protocol.WriterEpochTryCreate(1)
	operation, _ := contracts.OperationIdTryCreate("runtime")
	idempotency, _ := contracts.IdempotencyKeyTryCreate("ingress-test")
	attempt, _ := protocol.DeliveryAttemptTryCreate(1)
	payload := protocol.OpaquePayloadCopyFrom([]byte("payload"))
	digestBytes := sha256.Sum256(payload.Bytes())
	digest, _ := protocol.PayloadDigestTryCopyFrom(digestBytes[:])
	material := protocol.NewCommandEnvelope(version, cell, aggregate, generation, epoch, operation, idempotency,
		now, now.Add(time.Minute), attempt, payload, digest, protocol.OpaqueSignature{}).SignedMaterial
	signature, err := signer.Sign(material)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.NewCommandEnvelope(version, cell, aggregate, generation, epoch, operation, idempotency,
		now, now.Add(time.Minute), attempt, payload, digest, signature)
}

func mustIngressSPKI(t *testing.T, key *ecdsa.PublicKey) []byte {
	t.Helper()
	value, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func startIngressTestNATS(t *testing.T) *nats.Conn {
	t.Helper()
	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatal(err)
	}
	instance.Start()
	t.Cleanup(func() { instance.Shutdown(); instance.WaitForShutdown() })
	if !instance.ReadyForConnections(time.Second) {
		t.Fatal(errors.New("test NATS server did not become ready"))
	}
	connection, err := nats.Connect(instance.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	return connection
}
