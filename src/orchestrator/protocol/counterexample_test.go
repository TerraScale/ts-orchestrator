// Counterexample coverage for protocol validation invariants.
// The reflection-based closed-surface tests have no Go equivalent; the
// behavioral assertions are fully ported.
package protocol

import (
	"strings"
	"testing"
	"time"
)

func acceptTestEnvelope(t *testing.T, envelope CommandEnvelope, now time.Time) CommandValidationResult {
	t.Helper()
	context, err := NewCommandValidationContext(
		envelope.Cell,
		envelope.AggregateId,
		envelope.DesiredGeneration,
		envelope.WriterEpoch,
		[]ProtocolRevision{testProtocol(1), testProtocol(3)},
		2*time.Minute,
		outcomeDigestVerifier{outcome: VerificationOutcomeValid},
		outcomeSignatureVerifier{outcome: VerificationOutcomeValid})
	if err != nil {
		t.Fatalf("context construction failed: %v", err)
	}

	return CommandEnvelopeValidator.Validate(&envelope, context, now)
}

func TestAcceptedValidationReceiptDistinguishesTheExactProtocolAndCommand(t *testing.T) {
	context := validContext(func(o *validContextOption) {
		o.acceptedProtocols = []ProtocolRevision{testProtocol(1), testProtocol(3)}
	})
	n := validEnvelope(
		func(o *validEnvelopeOption) { o.protocol = ptrOf(testProtocol(3)) },
		func(o *validEnvelopeOption) { o.generation = ptrOf(testGeneration(11)) },
		func(o *validEnvelopeOption) { o.operation = ptrOf(testOperation("operation/n")) },
		func(o *validEnvelopeOption) { o.idempotency = ptrOf(testIdempotency("idempotency/n")) })
	nMinusOne := validEnvelope(
		func(o *validEnvelopeOption) { o.protocol = ptrOf(testProtocol(1)) },
		func(o *validEnvelopeOption) { o.generation = ptrOf(testGeneration(10)) },
		func(o *validEnvelopeOption) { o.operation = ptrOf(testOperation("operation/n-minus-one")) },
		func(o *validEnvelopeOption) { o.idempotency = ptrOf(testIdempotency("idempotency/n-minus-one")) })

	acceptedN := CommandEnvelopeValidator.Validate(&n, context, protocolNow)
	acceptedNMinusOne := CommandEnvelopeValidator.Validate(&nMinusOne, context, protocolNow)

	if !acceptedN.IsValid() || !acceptedNMinusOne.IsValid() {
		t.Fatal("both protocol revisions must be accepted")
	}

	if acceptedN.Equal(acceptedNMinusOne) {
		t.Fatal("the receipt must distinguish the exact protocol and command")
	}
}

func TestAcceptanceRetainsEveryApprovedFieldButNotTheRawPayload(t *testing.T) {
	payloadSecret := []byte("payload-secret")
	digestSecret := []byte("digest-secret")
	signatureSecret := []byte("signature-secret")
	validatedAt := protocolNow.Add(17 * time.Second)
	envelope := validEnvelope(
		func(o *validEnvelopeOption) { o.protocol = ptrOf(testProtocol(3)) },
		func(o *validEnvelopeOption) { o.generation = ptrOf(testGeneration(11)) },
		func(o *validEnvelopeOption) { o.epoch = ptrOf(testEpoch(8)) },
		func(o *validEnvelopeOption) { o.operation = ptrOf(testOperation("operation/exact")) },
		func(o *validEnvelopeOption) { o.idempotency = ptrOf(testIdempotency("idempotency/exact")) },
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(-2 * time.Minute)) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(2 * time.Minute)) },
		func(o *validEnvelopeOption) { o.attempt = ptrOf(testAttempt(3)) },
		func(o *validEnvelopeOption) { o.payload = ptrOf(OpaquePayloadCopyFrom(payloadSecret)) },
		func(o *validEnvelopeOption) { o.digest = ptrOf(testDigest(digestSecret)) },
		func(o *validEnvelopeOption) { o.signature = ptrOf(testSignature(signatureSecret)) })
	context := validContext(
		func(o *validContextOption) { o.minimumGeneration = ptrOf(testGeneration(11)) },
		func(o *validContextOption) { o.minimumEpoch = ptrOf(testEpoch(8)) },
		func(o *validContextOption) {
			o.acceptedProtocols = []ProtocolRevision{testProtocol(1), testProtocol(3)}
		},
		func(o *validContextOption) {
			o.digestVerifier = outcomeDigestVerifier{outcome: VerificationOutcomeValid}
		})

	result := CommandEnvelopeValidator.Validate(&envelope, context, validatedAt)
	if !result.IsValid() || result.Acceptance == nil {
		t.Fatalf("acceptance missing: %v", result.Error)
	}

	receipt := result.Acceptance
	if receipt.ProtocolVersion != envelope.ProtocolVersion || receipt.Cell != envelope.Cell ||
		receipt.AggregateId != envelope.AggregateId || receipt.DesiredGeneration != envelope.DesiredGeneration ||
		receipt.WriterEpoch != envelope.WriterEpoch || receipt.OperationId != envelope.OperationId ||
		receipt.IdempotencyKey != envelope.IdempotencyKey || !receipt.IssuedAt.Equal(envelope.IssuedAt) ||
		!receipt.ExpiresAt.Equal(envelope.ExpiresAt) || receipt.Attempt != envelope.Attempt ||
		!receipt.PayloadDigest.Equal(envelope.PayloadDigest) || !receipt.Signature.Equal(envelope.Signature) ||
		!receipt.ValidatedAt.Equal(validatedAt) {
		t.Fatal("receipt fields differ from the accepted envelope")
	}

	rendered := receipt.String()
	if strings.Contains(rendered, string(payloadSecret)) ||
		strings.Contains(rendered, string(digestSecret)) ||
		strings.Contains(rendered, string(signatureSecret)) {
		t.Fatalf("receipt leaked secret material: %s", rendered)
	}

	if !strings.Contains(rendered, "PayloadDigest = <redacted>") || !strings.Contains(rendered, "Signature = <redacted>") {
		t.Fatal("receipt must redact the digest and signature")
	}
}

func TestIdenticalReplayIsEqualAndEachReceiptFieldParticipatesInEquality(t *testing.T) {
	baselineEnvelope := validEnvelope()
	baseline := acceptTestEnvelope(t, baselineEnvelope, protocolNow)
	if !acceptTestEnvelope(t, baselineEnvelope, protocolNow).Equal(baseline) {
		t.Fatal("identical replay must be equal")
	}

	variants := []struct {
		envelope CommandEnvelope
		now      time.Time
	}{
		{validEnvelope(func(o *validEnvelopeOption) { o.protocol = ptrOf(testProtocol(3)) }), protocolNow},
		{validEnvelope(func(o *validEnvelopeOption) { o.cell = ptrOf(testCell("sfo")) }), protocolNow},
		{validEnvelope(func(o *validEnvelopeOption) { o.aggregate = ptrOf(testAggregate("allocation/other")) }), protocolNow},
		{validEnvelope(func(o *validEnvelopeOption) { o.generation = ptrOf(testGeneration(11)) }), protocolNow},
		{validEnvelope(func(o *validEnvelopeOption) { o.epoch = ptrOf(testEpoch(8)) }), protocolNow},
		{validEnvelope(func(o *validEnvelopeOption) { o.operation = ptrOf(testOperation("operation/other")) }), protocolNow},
		{validEnvelope(func(o *validEnvelopeOption) { o.idempotency = ptrOf(testIdempotency("idempotency/other")) }), protocolNow},
		{validEnvelope(func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(-30 * time.Second)) }), protocolNow},
		{validEnvelope(func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(30 * time.Second)) }), protocolNow},
		{validEnvelope(func(o *validEnvelopeOption) { o.attempt = ptrOf(testAttempt(2)) }), protocolNow},
		{validEnvelope(func(o *validEnvelopeOption) { o.digest = ptrOf(testDigest([]byte{4, 3, 2, 1})) }), protocolNow},
		{validEnvelope(func(o *validEnvelopeOption) { o.signature = ptrOf(testSignature([]byte{6, 7, 8, 9})) }), protocolNow},
		{baselineEnvelope, protocolNow.Add(100)},
	}

	for index, variant := range variants {
		if acceptTestEnvelope(t, variant.envelope, variant.now).Equal(baseline) {
			t.Fatalf("variant %d must not equal the baseline", index)
		}
	}
}

func TestRejectionsAndDefaultNeverCarryAnAcceptance(t *testing.T) {
	var zero CommandValidationResult
	if zero.Acceptance != nil {
		t.Fatal("default result must carry no acceptance")
	}

	for protocol := int64(3); protocol <= 33; protocol++ {
		envelope := validEnvelope(func(o *validEnvelopeOption) { o.protocol = ptrOf(testProtocol(protocol)) })
		result := CommandEnvelopeValidator.Validate(&envelope, validContext(), protocolNow)
		if result.IsValid() || result.Acceptance != nil {
			t.Fatalf("protocol %d must be rejected without an acceptance", protocol)
		}
	}
}
