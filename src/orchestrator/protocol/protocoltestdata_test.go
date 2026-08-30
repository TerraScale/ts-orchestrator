// Port of tests/TerraScale.Orchestrator.Protocol.Tests/ProtocolTestData.cs:
// shared fixtures and verifier doubles for the protocol test suite.
package protocol

import (
	"bytes"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
)

// protocolNow mirrors ProtocolTestData.Now.
var protocolNow = time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

// payloadBytes mirrors ProtocolTestData.PayloadBytes.
var payloadBytes = []byte{1, 2, 3, 4}

// signatureBytes mirrors ProtocolTestData.SignatureBytes.
var signatureBytes = []byte{9, 8, 7, 6}

func testCell(value string) contracts.CellId {
	id, _ := contracts.CellIdTryCreate(value)
	return id
}

func testAggregate(value string) contracts.AggregateId {
	id, _ := contracts.AggregateIdTryCreate(value)
	return id
}

func testOperation(value string) contracts.OperationId {
	id, _ := contracts.OperationIdTryCreate(value)
	return id
}

func testIdempotency(value string) contracts.IdempotencyKey {
	id, _ := contracts.IdempotencyKeyTryCreate(value)
	return id
}

func testProtocol(value int64) ProtocolRevision {
	revision, _ := ProtocolRevisionTryCreate(value)
	return revision
}

func testGeneration(value int64) DesiredGeneration {
	generation, _ := DesiredGenerationTryCreate(value)
	return generation
}

func testEpoch(value int64) WriterEpoch {
	epoch, _ := WriterEpochTryCreate(value)
	return epoch
}

func testAttempt(value int64) DeliveryAttempt {
	attempt, _ := DeliveryAttemptTryCreate(value)
	return attempt
}

func testDigest(source []byte) PayloadDigest {
	digest, _ := PayloadDigestTryCopyFrom(source)
	return digest
}

func testSignature(source []byte) OpaqueSignature {
	signature, _ := OpaqueSignatureTryCopyFrom(source)
	return signature
}

// validEnvelopeOption is one optional override of ProtocolTestData.ValidEnvelope.
type validEnvelopeOption struct {
	protocol    *ProtocolRevision
	cell        *contracts.CellId
	aggregate   *contracts.AggregateId
	generation  *DesiredGeneration
	epoch       *WriterEpoch
	operation   *contracts.OperationId
	idempotency *contracts.IdempotencyKey
	issuedAt    *time.Time
	expiresAt   *time.Time
	attempt     *DeliveryAttempt
	payload     *OpaquePayload
	digest      *PayloadDigest
	signature   *OpaqueSignature
}

func validEnvelope(overrides ...func(*validEnvelopeOption)) CommandEnvelope {
	options := validEnvelopeOption{
		protocol:    ptrOf(testProtocol(1)),
		cell:        ptrOf(testCell("gru")),
		aggregate:   ptrOf(testAggregate("allocation/42")),
		generation:  ptrOf(testGeneration(10)),
		epoch:       ptrOf(testEpoch(7)),
		operation:   ptrOf(testOperation("operation/abc")),
		idempotency: ptrOf(testIdempotency("idempotency/abc")),
		issuedAt:    ptrOf(protocolNow.Add(-time.Minute)),
		expiresAt:   ptrOf(protocolNow.Add(time.Minute)),
		attempt:     ptrOf(testAttempt(1)),
		payload:     ptrOf(OpaquePayloadCopyFrom(payloadBytes)),
		digest:      ptrOf(testDigest(payloadBytes)),
		signature:   ptrOf(testSignature(signatureBytes)),
	}

	for _, override := range overrides {
		override(&options)
	}

	envelope := NewCommandEnvelope(
		*options.protocol,
		*options.cell,
		*options.aggregate,
		*options.generation,
		*options.epoch,
		*options.operation,
		*options.idempotency,
		*options.issuedAt,
		*options.expiresAt,
		*options.attempt,
		*options.payload,
		*options.digest,
		*options.signature)
	// A nil payload pointer reproduces the C# `payload: null` test input.
	if options.payload == nil {
		envelope.Payload = OpaquePayload{}
		envelope.SignedMaterial.Payload = OpaquePayload{}
	}

	if options.digest == nil {
		envelope.PayloadDigest = PayloadDigest{}
		envelope.SignedMaterial.PayloadDigest = PayloadDigest{}
	}

	if options.signature == nil {
		envelope.Signature = OpaqueSignature{}
	}

	return envelope
}

func ptrOf[T any](value T) *T { return &value }

// validContextOption is one optional override of ProtocolTestData.ValidContext.
type validContextOption struct {
	expectedCell      *contracts.CellId
	expectedAggregate *contracts.AggregateId
	minimumGeneration *DesiredGeneration
	minimumEpoch      *WriterEpoch
	acceptedProtocols []ProtocolRevision
	skew              *time.Duration
	digestVerifier    IPayloadDigestVerifier
	signatureVerifier ICommandSignatureVerifier
}

func validContext(overrides ...func(*validContextOption)) *CommandValidationContext {
	options := validContextOption{
		expectedCell:      ptrOf(testCell("gru")),
		expectedAggregate: ptrOf(testAggregate("allocation/42")),
		minimumGeneration: ptrOf(testGeneration(10)),
		minimumEpoch:      ptrOf(testEpoch(7)),
		acceptedProtocols: []ProtocolRevision{testProtocol(1)},
		skew:              ptrOf(2 * time.Minute),
		digestVerifier:    &testDigestVerifier{},
		signatureVerifier: &testSignatureVerifier{},
	}

	for _, override := range overrides {
		override(&options)
	}

	context, err := NewCommandValidationContext(
		*options.expectedCell,
		*options.expectedAggregate,
		*options.minimumGeneration,
		*options.minimumEpoch,
		options.acceptedProtocols,
		*options.skew,
		options.digestVerifier,
		options.signatureVerifier)
	if err != nil {
		panic(err)
	}

	return context
}

// testDigestVerifier mirrors the C# TestDigestVerifier.
type testDigestVerifier struct {
	matches bool
	throws  bool
	calls   int
}

func newTestDigestVerifier(matches bool, throws bool) *testDigestVerifier {
	return &testDigestVerifier{matches: matches, throws: throws}
}

func (v *testDigestVerifier) Verify(payload OpaquePayload, expectedDigest PayloadDigest) VerificationOutcome {
	v.calls++
	if v.throws {
		panic("synthetic verifier failure")
	}

	if v.matches && bytes.Equal(payload.Bytes(), expectedDigest.Bytes()) {
		return VerificationOutcomeValid
	}

	return VerificationOutcomeInvalid
}

// testSignatureVerifier mirrors the C# TestSignatureVerifier.
type testSignatureVerifier struct {
	isValid       bool
	throws        bool
	calls         int
	lastMaterial  *CommandSignedMaterial
	lastSignature *OpaqueSignature
}

func newTestSignatureVerifier(isValid bool, throws bool) *testSignatureVerifier {
	return &testSignatureVerifier{isValid: isValid, throws: throws}
}

func (v *testSignatureVerifier) Verify(signedMaterial CommandSignedMaterial, signature OpaqueSignature) VerificationOutcome {
	v.calls++
	material := signedMaterial
	v.lastMaterial = &material
	sig := signature
	v.lastSignature = &sig
	if v.throws {
		panic("synthetic verifier failure")
	}

	if v.isValid {
		return VerificationOutcomeValid
	}

	return VerificationOutcomeInvalid
}

// outcomeVerifier fixtures mirror the Outcome*Verifier doubles.
type outcomeDigestVerifier struct {
	outcome VerificationOutcome
}

func (v outcomeDigestVerifier) Verify(OpaquePayload, PayloadDigest) VerificationOutcome {
	return v.outcome
}

type outcomeSignatureVerifier struct {
	outcome VerificationOutcome
}

func (v outcomeSignatureVerifier) Verify(CommandSignedMaterial, OpaqueSignature) VerificationOutcome {
	return v.outcome
}
