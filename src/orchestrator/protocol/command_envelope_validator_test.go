// Port of tests/TerraScale.Orchestrator.Protocol.Tests/CommandEnvelopeValidatorTests.cs:
// adversarial command replay, generation, epoch, and deadline tests for INV-005.
package protocol

import (
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
)

func TestDefaultValidationResultIsNotAccidentallyAccepted(t *testing.T) {
	var result CommandValidationResult
	if result.IsValid() {
		t.Fatal("default result must not be valid")
	}

	if result.Error != CommandValidationErrorUninitialized {
		t.Fatalf("Error = %v", result.Error)
	}
}

func TestValidEnvelopeIsAcceptedAndIdenticalReplayIsIdempotent(t *testing.T) {
	digestVerifier := &testDigestVerifier{matches: true}
	signatureVerifier := &testSignatureVerifier{isValid: true}
	context := validContext(
		func(o *validContextOption) { o.digestVerifier = digestVerifier },
		func(o *validContextOption) { o.signatureVerifier = signatureVerifier })
	envelope := validEnvelope()

	first := CommandEnvelopeValidator.Validate(&envelope, context, protocolNow)
	replay := CommandEnvelopeValidator.Validate(&envelope, context, protocolNow)

	if !first.IsValid() || first.Error != CommandValidationErrorNone {
		t.Fatalf("valid envelope rejected: %v", first.Error)
	}

	if !replay.Equal(first) {
		t.Fatal("identical replay must equal the first validation result")
	}

	if digestVerifier.calls != 2 || signatureVerifier.calls != 2 {
		t.Fatalf("verifier calls = %d/%d", digestVerifier.calls, signatureVerifier.calls)
	}
}

func TestMalformedEnvelopeFieldsFailBeforeVerifiers(t *testing.T) {
	digestVerifier := &testDigestVerifier{matches: true}
	signatureVerifier := &testSignatureVerifier{isValid: true}
	context := validContext(
		func(o *validContextOption) { o.digestVerifier = digestVerifier },
		func(o *validContextOption) { o.signatureVerifier = signatureVerifier })

	malformed := []CommandEnvelope{
		validEnvelope(func(o *validEnvelopeOption) { o.protocol = ptrOf(ProtocolRevision{}) }),
		validEnvelope(func(o *validEnvelopeOption) { o.cell = ptrOf(contracts.CellId{}) }),
		validEnvelope(func(o *validEnvelopeOption) { o.aggregate = ptrOf(contracts.AggregateId{}) }),
		validEnvelope(func(o *validEnvelopeOption) { o.generation = ptrOf(DesiredGeneration{}) }),
		validEnvelope(func(o *validEnvelopeOption) { o.epoch = ptrOf(WriterEpoch{}) }),
		validEnvelope(func(o *validEnvelopeOption) { o.operation = ptrOf(contracts.OperationId{}) }),
		validEnvelope(func(o *validEnvelopeOption) { o.idempotency = ptrOf(contracts.IdempotencyKey{}) }),
		validEnvelope(func(o *validEnvelopeOption) { o.attempt = ptrOf(DeliveryAttempt{}) }),
		validEnvelope(func(o *validEnvelopeOption) { o.payload = nil }),
		validEnvelope(func(o *validEnvelopeOption) { o.digest = nil }),
		validEnvelope(func(o *validEnvelopeOption) { o.signature = nil }),
	}

	for index := range malformed {
		result := CommandEnvelopeValidator.Validate(&malformed[index], context, protocolNow)
		if result.Error != CommandValidationErrorMalformedEnvelope {
			t.Fatalf("case %d: error = %v", index, result.Error)
		}
	}

	if digestVerifier.calls != 0 || signatureVerifier.calls != 0 {
		t.Fatalf("verifier calls = %d/%d", digestVerifier.calls, signatureVerifier.calls)
	}
}

func TestEnvelopeRejectsSignedMaterialThatDoesNotMatchEnvelopeFields(t *testing.T) {
	envelope := validEnvelope()
	envelope.SignedMaterial.WriterEpoch = testEpoch(999)
	signatureVerifier := &testSignatureVerifier{isValid: true}

	result := CommandEnvelopeValidator.Validate(
		&envelope,
		validContext(func(o *validContextOption) { o.signatureVerifier = signatureVerifier }),
		protocolNow)
	if result.Error != CommandValidationErrorMalformedEnvelope {
		t.Fatalf("error = %v, want malformed envelope", result.Error)
	}
	if signatureVerifier.calls != 0 {
		t.Fatal("a mismatched signed material must not reach the signature verifier")
	}
}

func TestInvalidContextIsClosedAndPrecedesEnvelopeValidation(t *testing.T) {
	validEnvelopeValue := validEnvelope()
	skew := time.Duration(0)

	invalidContexts := []*CommandValidationContext{
		nil,
		mustContext(t, contracts.CellId{}, testAggregate("allocation/42"), testGeneration(10), testEpoch(7),
			[]ProtocolRevision{testProtocol(1)}, skew, &testDigestVerifier{matches: true}, &testSignatureVerifier{isValid: true}),
		mustContext(t, testCell("gru"), contracts.AggregateId{}, testGeneration(10), testEpoch(7),
			[]ProtocolRevision{testProtocol(1)}, skew, &testDigestVerifier{matches: true}, &testSignatureVerifier{isValid: true}),
		mustContext(t, testCell("gru"), testAggregate("allocation/42"), DesiredGeneration{}, testEpoch(7),
			[]ProtocolRevision{testProtocol(1)}, skew, &testDigestVerifier{matches: true}, &testSignatureVerifier{isValid: true}),
		mustContext(t, testCell("gru"), testAggregate("allocation/42"), testGeneration(10), WriterEpoch{},
			[]ProtocolRevision{testProtocol(1)}, skew, &testDigestVerifier{matches: true}, &testSignatureVerifier{isValid: true}),
		mustContext(t, testCell("gru"), testAggregate("allocation/42"), testGeneration(10), testEpoch(7),
			[]ProtocolRevision{}, skew, &testDigestVerifier{matches: true}, &testSignatureVerifier{isValid: true}),
		mustContext(t, testCell("gru"), testAggregate("allocation/42"), testGeneration(10), testEpoch(7),
			[]ProtocolRevision{{}}, skew, &testDigestVerifier{matches: true}, &testSignatureVerifier{isValid: true}),
		mustContext(t, testCell("gru"), testAggregate("allocation/42"), testGeneration(10), testEpoch(7),
			[]ProtocolRevision{testProtocol(1)}, -100, &testDigestVerifier{matches: true}, &testSignatureVerifier{isValid: true}),
		mustContext(t, testCell("gru"), testAggregate("allocation/42"), testGeneration(10), testEpoch(7),
			[]ProtocolRevision{testProtocol(1)}, skew, nil, &testSignatureVerifier{isValid: true}),
		mustContext(t, testCell("gru"), testAggregate("allocation/42"), testGeneration(10), testEpoch(7),
			[]ProtocolRevision{testProtocol(1)}, skew, &testDigestVerifier{matches: true}, nil),
	}

	for index, context := range invalidContexts {
		result := CommandEnvelopeValidator.Validate(&validEnvelopeValue, context, protocolNow)
		if result.Error != CommandValidationErrorInvalidValidationContext {
			t.Fatalf("context %d: error = %v", index, result.Error)
		}
	}
}

func mustContext(
	t *testing.T,
	cell contracts.CellId,
	aggregate contracts.AggregateId,
	generation DesiredGeneration,
	epoch WriterEpoch,
	accepted []ProtocolRevision,
	skew time.Duration,
	digest IPayloadDigestVerifier,
	signature ICommandSignatureVerifier,
) *CommandValidationContext {
	t.Helper()
	context, err := NewCommandValidationContext(cell, aggregate, generation, epoch, accepted, skew, digest, signature)
	if err != nil {
		t.Fatalf("context construction failed: %v", err)
	}

	return context
}

func TestAcceptedProtocolVersionsAreDefensivelyCopied(t *testing.T) {
	accepted := []ProtocolRevision{testProtocol(1)}
	context := validContext(func(o *validContextOption) { o.acceptedProtocols = accepted })
	accepted[0] = testProtocol(2)

	envelope := validEnvelope()
	result := CommandEnvelopeValidator.Validate(&envelope, context, protocolNow)
	if !result.IsValid() {
		t.Fatalf("defensive copy failed: %v", result.Error)
	}
}

func TestUnsupportedProtocolPrecedesTimeAndIdentityChecks(t *testing.T) {
	envelope := validEnvelope(
		func(o *validEnvelopeOption) { o.protocol = ptrOf(testProtocol(2)) },
		func(o *validEnvelopeOption) { o.cell = ptrOf(testCell("wrong")) },
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(2 * time.Hour)) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(time.Hour)) })

	result := CommandEnvelopeValidator.Validate(&envelope, validContext(), protocolNow)
	if result.Error != CommandValidationErrorUnsupportedProtocolVersion {
		t.Fatalf("error = %v", result.Error)
	}
}

func TestEqualValidityEndpointsAreAllowedButReversedWindowIsNeverResurrected(t *testing.T) {
	equal := validEnvelope(
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow) })
	reversed := validEnvelope(
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(24 * time.Hour)) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(-24 * time.Hour)) })
	// TimeSpan.MaxValue is far beyond Go's duration range; the largest duration
	// stands in for it.
	context := validContext(func(o *validContextOption) { o.skew = ptrOf(time.Duration(1<<62 - 1)) })

	if !CommandEnvelopeValidator.Validate(&equal, context, protocolNow).IsValid() {
		t.Fatal("equal validity endpoints must be accepted")
	}

	if CommandEnvelopeValidator.Validate(&reversed, context, protocolNow).Error != CommandValidationErrorInvalidValidityWindow {
		t.Fatal("reversed validity window must be rejected")
	}
}

func TestClockSkewBoundariesAreInclusiveAndOneTickBeyondIsRejected(t *testing.T) {
	skew := 2 * time.Minute
	context := validContext(func(o *validContextOption) { o.skew = ptrOf(skew) })
	issueBoundary := validEnvelope(
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(skew)) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(3 * time.Minute)) })
	expiryBoundary := validEnvelope(
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(-3 * time.Minute)) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(-skew)) })
	issueBeyond := validEnvelope(
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(skew + 100)) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(3 * time.Minute)) })
	expiryBeyond := validEnvelope(
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(-3 * time.Minute)) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(-skew - 100)) })

	if !CommandEnvelopeValidator.Validate(&issueBoundary, context, protocolNow).IsValid() {
		t.Fatal("issue boundary must be accepted")
	}

	if !CommandEnvelopeValidator.Validate(&expiryBoundary, context, protocolNow).IsValid() {
		t.Fatal("expiry boundary must be accepted")
	}

	if CommandEnvelopeValidator.Validate(&issueBeyond, context, protocolNow).Error != CommandValidationErrorNotYetValid {
		t.Fatal("issue beyond skew must be NotYetValid")
	}

	if CommandEnvelopeValidator.Validate(&expiryBeyond, context, protocolNow).Error != CommandValidationErrorExpired {
		t.Fatal("expiry beyond skew must be Expired")
	}
}

func TestSkewComparisonsDoNotOverflowAtDatetimeExtremes(t *testing.T) {
	context := validContext(func(o *validContextOption) { o.skew = ptrOf(time.Duration(0)) })
	dotNetMaxValue := time.Date(9999, 12, 31, 23, 59, 59, 999999900, time.UTC)
	dotNetMinValue := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	farFuture := validEnvelope(
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(dotNetMaxValue.Add(-100)) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(dotNetMaxValue) })
	farPast := validEnvelope(
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(dotNetMinValue) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(dotNetMinValue.Add(100)) })

	if CommandEnvelopeValidator.Validate(&farFuture, context, dotNetMinValue).Error !=
		CommandValidationErrorNotYetValid {
		t.Fatal("far-future envelope must be NotYetValid")
	}

	if CommandEnvelopeValidator.Validate(&farPast, context, dotNetMaxValue).Error !=
		CommandValidationErrorExpired {
		t.Fatal("far-past envelope must be Expired")
	}
}

func TestWrongCellPrecedesInvalidSignatureAndWrongIdentityIsTyped(t *testing.T) {
	signatureVerifier := &testSignatureVerifier{isValid: false}
	context := validContext(func(o *validContextOption) { o.signatureVerifier = signatureVerifier })
	wrongCell := validEnvelope(func(o *validEnvelopeOption) { o.cell = ptrOf(testCell("sfo")) })
	wrongIdentity := validEnvelope(func(o *validEnvelopeOption) { o.aggregate = ptrOf(testAggregate("allocation/other")) })

	if CommandEnvelopeValidator.Validate(&wrongCell, context, protocolNow).Error != CommandValidationErrorWrongCell {
		t.Fatal("wrong cell must be typed")
	}

	if signatureVerifier.calls != 0 {
		t.Fatal("signature verifier must not run before the cell check")
	}

	if CommandEnvelopeValidator.Validate(&wrongIdentity, context, protocolNow).Error != CommandValidationErrorWrongAggregateIdentity {
		t.Fatal("wrong identity must be typed")
	}

	if signatureVerifier.calls != 0 {
		t.Fatal("signature verifier must not run before the identity check")
	}
}

func TestLowerGenerationAndEpochAreStaleWhileEqualBoundariesPass(t *testing.T) {
	context := validContext(
		func(o *validContextOption) { o.minimumGeneration = ptrOf(testGeneration(10)) },
		func(o *validContextOption) { o.minimumEpoch = ptrOf(testEpoch(7)) })

	staleGeneration := validEnvelope(func(o *validEnvelopeOption) { o.generation = ptrOf(testGeneration(9)) })
	if CommandEnvelopeValidator.Validate(&staleGeneration, context, protocolNow).Error != CommandValidationErrorStaleGeneration {
		t.Fatal("stale generation must be typed")
	}

	equalGeneration := validEnvelope(func(o *validEnvelopeOption) { o.generation = ptrOf(testGeneration(10)) })
	if !CommandEnvelopeValidator.Validate(&equalGeneration, context, protocolNow).IsValid() {
		t.Fatal("equal generation must pass")
	}

	staleEpoch := validEnvelope(func(o *validEnvelopeOption) { o.epoch = ptrOf(testEpoch(6)) })
	if CommandEnvelopeValidator.Validate(&staleEpoch, context, protocolNow).Error != CommandValidationErrorStaleWriterEpoch {
		t.Fatal("stale epoch must be typed")
	}

	equalEpoch := validEnvelope(func(o *validEnvelopeOption) { o.epoch = ptrOf(testEpoch(7)) })
	if !CommandEnvelopeValidator.Validate(&equalEpoch, context, protocolNow).IsValid() {
		t.Fatal("equal epoch must pass")
	}

	both := validEnvelope(
		func(o *validEnvelopeOption) { o.generation = ptrOf(testGeneration(9)) },
		func(o *validEnvelopeOption) { o.epoch = ptrOf(testEpoch(6)) })
	if CommandEnvelopeValidator.Validate(&both, context, protocolNow).Error != CommandValidationErrorStaleGeneration {
		t.Fatal("stale generation must take precedence")
	}
}

func TestDigestMismatchPrecedesSignatureAndInvalidSignatureIsTyped(t *testing.T) {
	signatureVerifier := &testSignatureVerifier{isValid: false}
	mismatchContext := validContext(
		func(o *validContextOption) { o.digestVerifier = newTestDigestVerifier(false, false) },
		func(o *validContextOption) { o.signatureVerifier = signatureVerifier })

	envelope := validEnvelope()
	mismatch := CommandEnvelopeValidator.Validate(&envelope, mismatchContext, protocolNow)
	if mismatch.Error != CommandValidationErrorPayloadDigestMismatch {
		t.Fatalf("error = %v", mismatch.Error)
	}

	if signatureVerifier.calls != 0 {
		t.Fatal("signature verifier must not run after a digest mismatch")
	}

	second := validEnvelope()
	invalidSignature := CommandEnvelopeValidator.Validate(
		&second,
		validContext(func(o *validContextOption) { o.signatureVerifier = newTestSignatureVerifier(false, false) }),
		protocolNow)
	if invalidSignature.Error != CommandValidationErrorInvalidSignature {
		t.Fatalf("error = %v", invalidSignature.Error)
	}
}

func TestVerifierExceptionsMapToClosedErrorsWithoutExceptionText(t *testing.T) {
	envelopeOne := validEnvelope()
	envelopeTwo := validEnvelope()
	digestFailure := CommandEnvelopeValidator.Validate(
		&envelopeOne,
		validContext(func(o *validContextOption) { o.digestVerifier = newTestDigestVerifier(true, true) }),
		protocolNow)
	signatureFailure := CommandEnvelopeValidator.Validate(
		&envelopeTwo,
		validContext(func(o *validContextOption) { o.signatureVerifier = newTestSignatureVerifier(true, true) }),
		protocolNow)

	if digestFailure.Error != CommandValidationErrorPayloadDigestVerificationFailed {
		t.Fatalf("digest error = %v", digestFailure.Error)
	}

	if signatureFailure.Error != CommandValidationErrorSignatureVerificationFailed {
		t.Fatalf("signature error = %v", signatureFailure.Error)
	}

	if digestFailure.String() == "synthetic verifier failure" || signatureFailure.String() == "synthetic verifier failure" {
		t.Fatal("result must not echo verifier exception text")
	}
}

func TestSignatureVerifierReceivesAllSignedFieldsAndEnforcesSignerPolicy(t *testing.T) {
	verifier := &testSignatureVerifier{isValid: false}
	envelope := validEnvelope()

	result := CommandEnvelopeValidator.Validate(
		&envelope,
		validContext(func(o *validContextOption) { o.signatureVerifier = verifier }),
		protocolNow)

	if result.Error != CommandValidationErrorInvalidSignature {
		t.Fatalf("error = %v", result.Error)
	}

	if verifier.lastMaterial == nil {
		t.Fatal("verifier must receive the signed material")
	}

	material := verifier.lastMaterial
	if material.ProtocolVersion != envelope.ProtocolVersion || material.Cell != envelope.Cell ||
		material.AggregateId != envelope.AggregateId || material.DesiredGeneration != envelope.DesiredGeneration ||
		material.WriterEpoch != envelope.WriterEpoch || material.OperationId != envelope.OperationId ||
		material.IdempotencyKey != envelope.IdempotencyKey || !material.IssuedAt.Equal(envelope.IssuedAt) ||
		!material.ExpiresAt.Equal(envelope.ExpiresAt) || material.Attempt != envelope.Attempt ||
		!material.Payload.Equal(envelope.Payload) || !material.PayloadDigest.Equal(envelope.PayloadDigest) {
		t.Fatal("signed material fields differ from the envelope")
	}

	if verifier.lastSignature == nil || !verifier.lastSignature.Equal(envelope.Signature) {
		t.Fatal("verifier must receive the exact signature")
	}

	if material.String() != "<command-signed-material>" {
		t.Fatalf("material renders %q", material.String())
	}
}
