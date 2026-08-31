package protocol

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestEnvelopeCarriesEveryRequiredField(t *testing.T) {
	envelope := validEnvelope()

	if envelope.ProtocolVersion != testProtocol(1) {
		t.Fatalf("ProtocolVersion = %v", envelope.ProtocolVersion)
	}

	if envelope.Cell != testCell("gru") {
		t.Fatalf("Cell = %v", envelope.Cell)
	}

	if envelope.AggregateId != testAggregate("allocation/42") {
		t.Fatalf("AggregateId = %v", envelope.AggregateId)
	}

	if envelope.DesiredGeneration != testGeneration(10) {
		t.Fatalf("DesiredGeneration = %v", envelope.DesiredGeneration)
	}

	if envelope.WriterEpoch != testEpoch(7) {
		t.Fatalf("WriterEpoch = %v", envelope.WriterEpoch)
	}

	if envelope.OperationId != testOperation("operation/abc") {
		t.Fatalf("OperationId = %v", envelope.OperationId)
	}

	if envelope.IdempotencyKey != testIdempotency("idempotency/abc") {
		t.Fatalf("IdempotencyKey = %v", envelope.IdempotencyKey)
	}

	if !envelope.IssuedAt.Equal(protocolNow.Add(-time.Minute)) {
		t.Fatalf("IssuedAt = %v", envelope.IssuedAt)
	}

	if !envelope.ExpiresAt.Equal(protocolNow.Add(time.Minute)) {
		t.Fatalf("ExpiresAt = %v", envelope.ExpiresAt)
	}

	if envelope.Attempt != testAttempt(1) {
		t.Fatalf("Attempt = %v", envelope.Attempt)
	}

	if !bytes.Equal(envelope.Payload.Bytes(), payloadBytes) {
		t.Fatal("Payload bytes differ")
	}

	if !bytes.Equal(envelope.PayloadDigest.Bytes(), payloadBytes) {
		t.Fatal("PayloadDigest bytes differ")
	}

	if !bytes.Equal(envelope.Signature.Bytes(), signatureBytes) {
		t.Fatal("Signature bytes differ")
	}
}

func TestEnvelopeFormattingNeverRendersPayloadDigestOrSignature(t *testing.T) {
	payloadSecret := "payload-super-secret"
	digestSecret := "digest-super-secret"
	signatureSecret := "signature-super-secret"
	envelope := validEnvelope(
		func(o *validEnvelopeOption) { o.payload = ptrOf(OpaquePayloadCopyFrom([]byte(payloadSecret))) },
		func(o *validEnvelopeOption) { o.digest = ptrOf(testDigest([]byte(digestSecret))) },
		func(o *validEnvelopeOption) { o.signature = ptrOf(testSignature([]byte(signatureSecret))) })

	rendered := envelope.String()

	if strings.Contains(rendered, payloadSecret) || strings.Contains(rendered, digestSecret) ||
		strings.Contains(rendered, signatureSecret) {
		t.Fatalf("rendered envelope leaked secret material: %s", rendered)
	}

	if !strings.Contains(rendered, "Payload = <redacted>") {
		t.Fatal("rendered envelope must redact the payload")
	}

	if !strings.Contains(rendered, "Signature = <redacted>") {
		t.Fatal("rendered envelope must redact the signature")
	}
}

func TestDotNetDateTimeOffsetHelpersPreserveLocalWallClockAndOffset(t *testing.T) {
	zone := time.FixedZone("BRT", -3*60*60)
	value := time.Date(2026, 8, 30, 12, 4, 5, 123456700, zone)

	if got, want := dotNetTicks(value), int64(639236882451234567); got != want {
		t.Fatalf("DateTimeOffset ticks = %d, want %d", got, want)
	}
	if got, want := formatDotNetRoundTrip(value), "2026-08-30T12:04:05.1234567-03:00"; got != want {
		t.Fatalf("DateTimeOffset round-trip = %q, want %q", got, want)
	}

	utc := value.UTC()
	if dotNetTicks(value) == dotNetTicks(utc) {
		t.Fatal("local DateTimeOffset ticks must retain the wall-clock offset")
	}
}
