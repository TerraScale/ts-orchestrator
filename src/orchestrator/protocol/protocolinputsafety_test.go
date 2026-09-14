package protocol

import (
	"strings"
	"testing"
)

func TestAcceptedVersionCaptureAcceptsExactMaximumWithoutConsultingCollectionCount(t *testing.T) {
	maximum := ProtocolTechnicalInputLimits.MaximumAcceptedProtocolVersionCount()
	versions := make([]ProtocolRevision, maximum)
	for index := range versions {
		versions[index] = testProtocol(int64(index + 1))
	}

	envelope := validEnvelope()
	result := CommandEnvelopeValidator.Validate(
		&envelope,
		validContext(func(o *validContextOption) { o.acceptedProtocols = versions }),
		protocolNow)

	if !result.IsValid() {
		t.Fatalf("exact maximum must be captured: %v", result.Error)
	}
}

func TestAcceptedVersionCaptureRejectsMaximumPlusOne(t *testing.T) {
	maximum := ProtocolTechnicalInputLimits.MaximumAcceptedProtocolVersionCount()
	versions := make([]ProtocolRevision, maximum+1)
	for index := range versions {
		versions[index] = testProtocol(int64(index + 1))
	}

	_, err := NewCommandValidationContext(
		testCell("gru"),
		testAggregate("allocation/42"),
		testGeneration(10),
		testEpoch(7),
		versions,
		0,
		&testDigestVerifier{matches: true},
		&testSignatureVerifier{isValid: true})

	if err == nil {
		t.Fatal("maximum plus one versions must fail closed")
	}

	if !strings.Contains(err.Error(), "acceptedProtocolVersions") {
		t.Fatalf("failure must name the parameter: %v", err)
	}

	if strings.Contains(err.Error(), "iterator-secret") {
		t.Fatal("failure must not echo enumerator internals")
	}
}

func TestCommandVerifierPanicsFailClosedWithoutLeakingDetails(t *testing.T) {
	panickingDigest := &panickingDigestVerifier{}
	panickingSignature := &panickingSignatureVerifier{}

	envelopeOne := validEnvelope()
	digestFailure := CommandEnvelopeValidator.Validate(
		&envelopeOne,
		validContext(func(o *validContextOption) { o.digestVerifier = panickingDigest }),
		protocolNow)

	envelopeTwo := validEnvelope()
	signatureFailure := CommandEnvelopeValidator.Validate(
		&envelopeTwo,
		validContext(func(o *validContextOption) { o.signatureVerifier = panickingSignature }),
		protocolNow)

	if digestFailure.Error != CommandValidationErrorPayloadDigestVerificationFailed {
		t.Fatalf("digest error = %v", digestFailure.Error)
	}

	if signatureFailure.Error != CommandValidationErrorSignatureVerificationFailed {
		t.Fatalf("signature error = %v", signatureFailure.Error)
	}
}

type panickingDigestVerifier struct{}

func (panickingDigestVerifier) Verify(OpaquePayload, PayloadDigest) VerificationOutcome {
	panic("synthetic verifier failure")
}

type panickingSignatureVerifier struct{}

func (panickingSignatureVerifier) Verify(CommandSignedMaterial, OpaqueSignature) VerificationOutcome {
	panic("synthetic verifier failure")
}
