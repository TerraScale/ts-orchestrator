package protocol

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEnvelopeV1GoldenVector(t *testing.T) {
	t.Parallel()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	issuedAt := time.Date(2026, time.September, 24, 12, 0, 0, 123456789, time.UTC)
	envelope, err := SignEnvelope(
		[]byte(`{"replicas":3,"name":"alpha"}`),
		EnvelopeScope{Region: "GRU", Kind: "test.command", Actor: "controller:gru", OperationID: "0000000000SP2S0FM13N018RM0", Generation: 3, Epoch: 7},
		issuedAt,
		issuedAt.Add(time.Minute),
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/envelope-v1.json")
	if err != nil {
		t.Fatalf("read golden envelope: %v", err)
	}
	if got, want := string(encoded), strings.TrimSpace(string(fixture)); got != want {
		t.Fatalf("encoded envelope mismatch\n got: %s\nwant: %s", got, want)
	}
	if envelope.KeyID != "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c" {
		t.Fatalf("KeyID() = %s", envelope.KeyID)
	}
	if envelope.Signature != "RgrB2ZI-RXrohAE749IyNk60xUQ9QzwAAJVBue_17-TXwNH2XTziznRj5qN8wnqWZFkqg8dwAiE2yFnvrq-_DA" {
		t.Fatalf("signature = %s", envelope.Signature)
	}
	var decoded Envelope
	if err := DecodeStrict(fixture, &decoded, DefaultMaxJSONBytes); err != nil {
		t.Fatalf("DecodeStrict(golden) error = %v", err)
	}
	if err := VerifyEnvelope(decoded, EnvelopeScope{
		Region: "GRU", Kind: "test.command", Actor: "controller:gru",
		OperationID: "0000000000SP2S0FM13N018RM0", Generation: 3, Epoch: 7,
	}, privateKey.Public().(ed25519.PublicKey), issuedAt, VerifyPolicy{
		MaxLifetime: time.Minute, ClockSkew: 0,
	}); err != nil {
		t.Fatalf("VerifyEnvelope(golden) error = %v", err)
	}
}

type strictPayload struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func TestDecodeStrictRejectsAmbiguousAndUnknownJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "duplicate top-level member", data: []byte(`{"name":"first","name":"second","count":1}`)},
		{name: "duplicate escaped member", data: []byte(`{"name":"first","na\u006de":"second","count":1}`)},
		{name: "nested duplicate member", data: []byte(`{"name":"first","count":1,"nested":{"x":1,"x":2}}`)},
		{name: "unknown member", data: []byte(`{"name":"worker","count":1,"extra":true}`)},
		{name: "trailing JSON value", data: []byte(`{"name":"worker","count":1} {}`)},
		{name: "invalid UTF-8", data: []byte{'{', '"', 'n', 'a', 'm', 'e', '"', ':', '"', 0xff, '"', ',', '"', 'c', 'o', 'u', 'n', 't', '"', ':', '1', '}'}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var payload strictPayload
			if err := DecodeStrict(test.data, &payload, DefaultMaxJSONBytes); err == nil {
				t.Fatal("DecodeStrict accepted invalid input")
			}
		})
	}
}

func TestDecodeTolerantSkipsOnlyUnknownMembers(t *testing.T) {
	t.Parallel()

	var payload strictPayload
	if err := DecodeTolerant([]byte(`{"name":"worker","count":1,"added":{"by":"newer binary"}}`), &payload, DefaultMaxJSONBytes); err != nil ||
		payload != (strictPayload{Name: "worker", Count: 1}) {
		t.Fatalf("DecodeTolerant(newer record) = %+v, %v", payload, err)
	}
	for _, data := range [][]byte{
		[]byte(`{"name":"first","name":"second","count":1}`),
		[]byte(`{"name":"first","count":1,"added":{"x":1,"x":2}}`),
		[]byte(`{"name":"worker","count":1} {}`),
		[]byte(`{"name":"worker","count":"1"}`),
		{'{', '"', 'n', 'a', 'm', 'e', '"', ':', '"', 0xff, '"', '}'},
	} {
		if err := DecodeTolerant(data, &strictPayload{}, DefaultMaxJSONBytes); err == nil {
			t.Fatalf("DecodeTolerant accepted %q", data)
		}
	}
	if err := DecodeTolerant([]byte(`{"name":"worker"}`), &strictPayload{}, 4); !errors.Is(err, ErrJSONTooLarge) {
		t.Fatalf("DecodeTolerant size limit error = %v", err)
	}
}

func TestDecodeStrictEnforcesSizeLimit(t *testing.T) {
	t.Parallel()

	var payload strictPayload
	err := DecodeStrict([]byte(`{"name":"worker","count":1}`), &payload, 4)
	if !errors.Is(err, ErrJSONTooLarge) {
		t.Fatalf("DecodeStrict error = %v, want ErrJSONTooLarge", err)
	}
}

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

func TestDecodeStrictRejectsDuplicateAndUnknownEnvelopeFields(t *testing.T) {
	t.Parallel()

	duplicate := []byte(`{"schemaVersion":1,"schemaVersion":1}`)
	unknown := []byte(`{"schemaVersion":1,"unexpected":true}`)
	for name, data := range map[string][]byte{"duplicate": duplicate, "unknown": unknown} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var envelope Envelope
			if err := DecodeStrict(data, &envelope, DefaultMaxJSONBytes); err == nil {
				t.Fatal("DecodeStrict accepted invalid envelope JSON")
			}
		})
	}
}

func TestSignEnvelopeRejectsDuplicateInvalidAndNonObjectPayload(t *testing.T) {
	t.Parallel()

	privateKey := testPrivateKey()
	for name, payload := range map[string][]byte{
		"duplicate member": []byte(`{"name":"first","name":"second"}`),
		"invalid UTF-8":    {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		"not an object":    []byte(`null`),
		"malformed":        []byte(`{"name":`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := SignEnvelope(payload, testScope(), fixedNow(), fixedNow().Add(time.Minute), privateKey); !errors.Is(err, ErrInvalidPayload) {
				t.Fatalf("SignEnvelope() error = %v, want ErrInvalidPayload", err)
			}
		})
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
		{
			name:      "wrong generation scope",
			mutate:    func(_ *Envelope, expected *EnvelopeScope) { expected.Generation++ },
			wantError: ErrScopeMismatch,
		},
		{
			name:      "changed issue time",
			mutate:    func(actual *Envelope, _ *EnvelopeScope) { actual.IssuedAt = actual.IssuedAt.Add(time.Second) },
			wantError: ErrBadSignature,
		},
		{
			name:      "changed payload",
			mutate:    func(actual *Envelope, _ *EnvelopeScope) { actual.Payload = []byte(`{"name":"attacker","count":4}`) },
			wantError: ErrBadSignature,
		},
		{
			name:      "changed key ID",
			mutate:    func(actual *Envelope, _ *EnvelopeScope) { actual.KeyID = "sha256:" + strings.Repeat("0", 64) },
			wantError: ErrKeyMismatch,
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

func TestVerifyEnvelopeEnforcesTimePolicy(t *testing.T) {
	t.Parallel()

	privateKey := testPrivateKey()
	now := fixedNow()
	publicKey := privateKey.Public().(ed25519.PublicKey)

	valid, err := SignEnvelope([]byte(`{"name":"worker","count":4}`), testScope(), now.Add(-time.Second), now.Add(time.Minute), privateKey)
	if err != nil {
		t.Fatalf("SignEnvelope() error = %v", err)
	}
	if err := VerifyEnvelope(valid, testScope(), publicKey, valid.ExpiresAt, testVerifyPolicy()); !errors.Is(err, ErrExpired) {
		t.Fatalf("VerifyEnvelope(at expiry) error = %v, want ErrExpired", err)
	}
	if err := VerifyEnvelope(valid, testScope(), publicKey, now.Add(-5*time.Second), testVerifyPolicy()); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("VerifyEnvelope(future issue) error = %v, want ErrNotYetValid", err)
	}
	if err := VerifyEnvelope(valid, testScope(), publicKey, now, VerifyPolicy{MaxLifetime: time.Second}); err == nil {
		t.Fatal("VerifyEnvelope accepted a lifetime longer than policy")
	}
}

func TestSubjectBuildersUseVersionedRegionalAndHashedAgentScopes(t *testing.T) {
	t.Parallel()

	query, err := QuerySubject("GRU", "status")
	if err != nil {
		t.Fatalf("QuerySubject() error = %v", err)
	}
	if want := "ts.orch.v1.gru.query.status"; query != want {
		t.Fatalf("QuerySubject() = %q, want %q", query, want)
	}
	command, err := CommandSubject("sfo", "scale-down")
	if err != nil || command != "ts.orch.v1.sfo.command.scale-down" {
		t.Fatalf("CommandSubject() = %q, %v", command, err)
	}
	global, err := GlobalControlSubject("promote")
	if err != nil || global != "ts.orch.v1.global.control.promote" {
		t.Fatalf("GlobalControlSubject() = %q, %v", global, err)
	}
	agent, err := AgentCommandSubject("GRU", "oci://node-42", "drain")
	if err != nil {
		t.Fatalf("AgentCommandSubject() error = %v", err)
	}
	if want := "ts.orch.v1.gru.agent." + HashToken("oci://node-42") + ".command.drain"; agent != want {
		t.Fatalf("AgentCommandSubject() = %q, want %q", agent, want)
	}
	reply, err := AgentReplySubject("GRU", "oci://node-42", "0000000000RCKH58KJ5M6FJATY")
	if err != nil || !strings.HasSuffix(reply, ".reply."+HashToken("0000000000RCKH58KJ5M6FJATY")[:32]) {
		t.Fatalf("AgentReplySubject() = %q, %v", reply, err)
	}
	observability, err := ObservabilitySubject("GRU", "snapshot")
	if err != nil || observability != "ts.orch.v1.gru.obs.snapshot" {
		t.Fatalf("ObservabilitySubject() = %q, %v", observability, err)
	}
	if wildcard := ObservabilityGrant("gru"); wildcard != "ts.orch.v1.gru.obs.>" {
		t.Fatalf("ObservabilityGrant() = %q", wildcard)
	}
	if wildcard := ObservabilityGrant("global"); wildcard != "" {
		t.Fatalf("ObservabilityGrant(global) = %q, want empty", wildcard)
	}
	if pattern := AnyRegionObservabilitySubject(ObservabilityDecisionsLeaf); pattern != "ts.orch.v1.*.obs.decisions" {
		t.Fatalf("AnyRegionObservabilitySubject() = %q", pattern)
	}
	if _, err := ObservabilitySubject("GRU", "snap.*"); !errors.Is(err, ErrInvalidSubjectToken) {
		t.Fatalf("ObservabilitySubject(injected token) error = %v, want ErrInvalidSubjectToken", err)
	}
	if _, err := QuerySubject("GLOBAL", "status"); !errors.Is(err, ErrInvalidSubjectToken) {
		t.Fatalf("QuerySubject(global region) error = %v, want ErrInvalidSubjectToken", err)
	}
	if _, err := CommandSubject("GRU", "bad.token"); !errors.Is(err, ErrInvalidSubjectToken) {
		t.Fatalf("CommandSubject(injected token) error = %v, want ErrInvalidSubjectToken", err)
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
