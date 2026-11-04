package protocol

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestEnvelopeRoundTripAndPayloadWhitespace(t *testing.T) {
	t.Parallel()

	privateKey := testPrivateKey()
	now := fixedNow()
	scope := testScope()
	envelope, err := SignEnvelope(
		[]byte("{ \"name\" : \"worker\", \"count\" : 4 }"), scope,
		now.Add(-time.Second), now.Add(time.Minute), privateKey,
	)
	if err != nil {
		t.Fatalf("SignEnvelope() error = %v", err)
	}
	if got, want := string(envelope.Payload), `{"name":"worker","count":4}`; got != want {
		t.Fatalf("compacted payload = %s, want %s", got, want)
	}

	wire, err := EncodeJSON(envelope)
	if err != nil {
		t.Fatalf("EncodeJSON() error = %v", err)
	}
	var decoded Envelope
	if err := DecodeStrict(wire, &decoded, DefaultMaxJSONBytes); err != nil {
		t.Fatalf("DecodeStrict(envelope) error = %v", err)
	}
	if err := VerifyEnvelope(decoded, scope, privateKey.Public().(ed25519.PublicKey), now, testVerifyPolicy()); err != nil {
		t.Fatalf("VerifyEnvelope() error = %v", err)
	}

	decoded.Payload = []byte("{\n  \"name\": \"worker\", \"count\": 4\n}")
	if err := VerifyEnvelope(decoded, scope, privateKey.Public().(ed25519.PublicKey), now, testVerifyPolicy()); err != nil {
		t.Fatalf("VerifyEnvelope() rejected whitespace-only payload reformat: %v", err)
	}
	decoded.Payload = []byte(`{"count":4,"name":"worker"}`)
	if err := VerifyEnvelope(decoded, scope, privateKey.Public().(ed25519.PublicKey), now, testVerifyPolicy()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("VerifyEnvelope(reordered payload) error = %v, want ErrBadSignature", err)
	}
}

func TestVerifyEnvelopeRejectsScopeKeyAndSignedFieldChanges(t *testing.T) {
	t.Parallel()

	privateKey := testPrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	now := fixedNow()
	envelope, err := SignEnvelope([]byte(`{"name":"worker","count":4}`), testScope(), now.Add(-time.Second), now.Add(time.Minute), privateKey)
	if err != nil {
		t.Fatalf("SignEnvelope() error = %v", err)
	}

	tests := []struct {
		name      string
		mutate    func(*Envelope, *EnvelopeScope)
		wantError error
	}{
		{
			name:      "wrong actor scope",
			mutate:    func(_ *Envelope, expected *EnvelopeScope) { expected.Actor = "controller:other" },
			wantError: ErrScopeMismatch,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			actual := envelope
			expected := testScope()
			test.mutate(&actual, &expected)
			if err := VerifyEnvelope(actual, expected, publicKey, now, testVerifyPolicy()); !errors.Is(err, test.wantError) {
				t.Fatalf("VerifyEnvelope() error = %v, want %v", err, test.wantError)
			}
		})
	}

	wrongKey := testPrivateKeyWithByte(0x27).Public().(ed25519.PublicKey)
	if err := VerifyEnvelope(envelope, testScope(), wrongKey, now, testVerifyPolicy()); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("VerifyEnvelope(wrong key) error = %v, want ErrKeyMismatch", err)
	}
}

func testPrivateKey() ed25519.PrivateKey {
	return testPrivateKeyWithByte(0x42)
}

func testPrivateKeyWithByte(value byte) ed25519.PrivateKey {
	seed := bytes.Repeat([]byte{value}, ed25519.SeedSize)
	return ed25519.NewKeyFromSeed(seed)
}

func testScope() EnvelopeScope {
	return EnvelopeScope{
		Region:      "gru",
		Kind:        "delivery.intent",
		Actor:       "controller:gru",
		OperationID: "0000000000RCKH58KJ5M6FJATY",
		Generation:  7,
		Epoch:       11,
	}
}

func testVerifyPolicy() VerifyPolicy {
	return VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 2 * time.Second}
}

func fixedNow() time.Time {
	return time.Date(2026, time.September, 24, 12, 0, 0, 123456789, time.UTC)
}
