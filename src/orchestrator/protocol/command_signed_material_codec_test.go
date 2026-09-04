package protocol

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCanonicalHashIsDeterministicAndCoversEveryMaterialField(t *testing.T) {
	original := validEnvelope()
	hash, err := CommandSignedMaterialCodec.Hash(&original.SignedMaterial)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	if hex.EncodeToString(hash[:]) != "f0c33bfb14f052c4ae3fba270f274fd922bdf02963e517dbaffec75a74c19c8b" {
		t.Fatalf("canonical hash = %s", hex.EncodeToString(hash[:]))
	}

	alternatives := []CommandEnvelope{
		validEnvelope(func(o *validEnvelopeOption) { o.protocol = ptrOf(testProtocol(3)) }),
		validEnvelope(func(o *validEnvelopeOption) { o.cell = ptrOf(testCell("sfo")) }),
		validEnvelope(func(o *validEnvelopeOption) { o.aggregate = ptrOf(testAggregate("allocation/43")) }),
		validEnvelope(func(o *validEnvelopeOption) { o.generation = ptrOf(testGeneration(11)) }),
		validEnvelope(func(o *validEnvelopeOption) { o.epoch = ptrOf(testEpoch(8)) }),
		validEnvelope(func(o *validEnvelopeOption) { o.operation = ptrOf(testOperation("operation/def")) }),
		validEnvelope(func(o *validEnvelopeOption) { o.idempotency = ptrOf(testIdempotency("idempotency/def")) }),
		validEnvelope(func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(-2 * time.Minute)) }),
		validEnvelope(func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(-time.Minute).Add(100)) }),
		validEnvelope(func(o *validEnvelopeOption) {
			issued := protocolNow.Add(-time.Minute).In(time.FixedZone("offset", 60*60))
			o.issuedAt = ptrOf(issued)
		}),
		validEnvelope(func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(2 * time.Minute)) }),
		validEnvelope(func(o *validEnvelopeOption) { o.attempt = ptrOf(testAttempt(2)) }),
		validEnvelope(func(o *validEnvelopeOption) { o.payload = ptrOf(OpaquePayloadCopyFrom([]byte{1, 2, 3, 5})) }),
		validEnvelope(func(o *validEnvelopeOption) { o.digest = ptrOf(testDigest([]byte{1, 2, 3, 5})) }),
	}

	replay := validEnvelope()
	replayHash, err := CommandSignedMaterialCodec.Hash(&replay.SignedMaterial)
	if err != nil {
		t.Fatalf("replay hash failed: %v", err)
	}

	if hash != replayHash {
		t.Fatal("canonical hash must be deterministic")
	}

	for index := range alternatives {
		alternativeHash, err := CommandSignedMaterialCodec.Hash(&alternatives[index].SignedMaterial)
		if err != nil {
			t.Fatalf("alternative %d hash failed: %v", index, err)
		}

		if alternativeHash == hash {
			t.Fatalf("alternative %d produced the same hash", index)
		}
	}
}

func TestCanonicalHashMatchesNonUtcWireTimestampVector(t *testing.T) {
	zone := time.FixedZone("BRT", -3*60*60)
	envelope := validEnvelope(
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(-time.Minute).In(zone)) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(time.Minute).In(zone)) })

	hash, err := CommandSignedMaterialCodec.Hash(&envelope.SignedMaterial)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	if got, want := hex.EncodeToString(hash[:]), "b10102726c4bc6a2b3decede3b23d726f08f44e60928b44cafaed7dee1aa51c2"; got != want {
		t.Fatalf("non-UTC canonical hash = %s, want %s", got, want)
	}
}

func TestInvalidWindowAndOversizedPayloadCannotReachASigner(t *testing.T) {
	invalidWindow := validEnvelope(
		func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow) },
		func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(-time.Second)) })
	oversizedPayload := make([]byte, 1024*1024+1)
	oversized := validEnvelope(func(o *validEnvelopeOption) { o.payload = ptrOf(OpaquePayloadCopyFrom(oversizedPayload)) })

	if _, err := CommandSignedMaterialCodec.Hash(&invalidWindow.SignedMaterial); !isInvalidData(err) {
		t.Fatalf("invalid window error = %v", err)
	}

	if _, err := CommandSignedMaterialCodec.Hash(&oversized.SignedMaterial); !isInvalidData(err) {
		t.Fatalf("oversized payload error = %v", err)
	}
}

func TestSigningIdentityBoundUsesV1UTF16CodeUnits(t *testing.T) {
	atLimit := strings.Repeat("\U0001F680", maximumIdentifierCharacters/2)
	accepted := validEnvelope(func(o *validEnvelopeOption) { o.cell = ptrOf(testCell(atLimit)) })
	if _, err := CommandSignedMaterialCodec.Encode(&accepted.SignedMaterial); err != nil {
		t.Fatalf("identity at the v1 code-unit bound was rejected: %v", err)
	}

	overLimit := atLimit + "a"
	rejected := validEnvelope(func(o *validEnvelopeOption) { o.cell = ptrOf(testCell(overLimit)) })
	if _, err := CommandSignedMaterialCodec.Encode(&rejected.SignedMaterial); !isInvalidData(err) {
		t.Fatalf("identity over the v1 code-unit bound error = %v", err)
	}
}

func isInvalidData(err error) bool {
	var invalid *InvalidDataError
	return errors.As(err, &invalid)
}
