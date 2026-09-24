package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEnvelopeRoundTripAndCanonicalWire(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	scope := testScope()
	payload, err := EncodePayload(map[string]any{"image": "ocid1.image", "digest": "abc", "generation": 7})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(payload, scope, now, now.Add(time.Minute), rootPrivate)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	wire, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("EncodeEnvelope() error = %v", err)
	}
	decoded, err := DecodeEnvelope(wire)
	if err != nil {
		t.Fatalf("DecodeEnvelope() error = %v", err)
	}
	if !bytes.Equal(wire, mustEncode(t, decoded)) {
		t.Fatal("envelope did not round-trip to identical canonical bytes")
	}
	verified, err := VerifyCurrent(decoded, scope, testKeyring(t, rootPublic), now, testPolicy())
	if err != nil || !bytes.Equal(verified, envelope.Payload) {
		t.Fatalf("VerifyCurrent() = %s, %v", verified, err)
	}
	if _, err := VerifyCurrent(decoded, testScopeWithCell("SFO"), testKeyring(t, rootPublic), now, testPolicy()); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("wrong-cell verification error = %v, want ErrScopeMismatch", err)
	}
	if _, err := VerifyCurrent(decoded, scope, testKeyring(t, rootPublic), now.Add(time.Minute), testPolicy()); !errors.Is(err, ErrExpired) {
		t.Fatalf("at-expiry verification error = %v, want ErrExpired", err)
	}
}

func TestDecodeEnvelopeRejectsAmbiguousOrNoncanonicalJSON(t *testing.T) {
	for _, wire := range [][]byte{
		[]byte(`{"schemaVersion":1,"schemaVersion":1}`),
		[]byte(`{"unknown":true}`),
		[]byte(" {\"schemaVersion\":1}"),
	} {
		if _, err := DecodeEnvelope(wire); err == nil {
			t.Fatalf("DecodeEnvelope(%s) unexpectedly succeeded", wire)
		}
	}
}

func TestEnvelopeRejectsMalleableSignatureAndTimestampRepresentations(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	envelope, err := Sign([]byte(`{"record":"immutable"}`), testScope(), now, now.Add(time.Minute), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	keys := testKeyring(t, rootPublic)
	policy := testPolicy()

	last := envelope.Signature[len(envelope.Signature)-1]
	lastIndex := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", last)
	if lastIndex < 0 || lastIndex&15 != 0 || lastIndex == 63 {
		t.Fatalf("unexpected canonical base64url signature suffix %q (index %d)", last, lastIndex)
	}
	unusedBitsVariant := envelope
	unusedBitsVariant.Signature = envelope.Signature[:len(envelope.Signature)-1] + string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[lastIndex+1])
	newlineVariant := envelope
	newlineVariant.Signature = envelope.Signature[:20] + "\n" + envelope.Signature[20:]
	for name, variant := range map[string]Envelope{
		"nonzero unused signature bits": unusedBitsVariant,
		"embedded signature newline":    newlineVariant,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyCurrent(variant, testScope(), keys, now, policy); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("VerifyCurrent() error = %v, want ErrBadSignature", err)
			}
			if _, err := EncodeEnvelope(variant); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("EncodeEnvelope() error = %v, want ErrBadSignature", err)
			}
			if _, err := Fingerprint(variant); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("Fingerprint() error = %v, want ErrBadSignature", err)
			}
			wire, err := json.Marshal(variant, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeEnvelope(wire); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("DecodeEnvelope() error = %v, want ErrBadSignature", err)
			}
		})
	}

	plusTwo := time.FixedZone("plus-two", 2*60*60)
	offsetVariant := envelope
	offsetVariant.IssuedAt = time.Date(2026, time.September, 24, 14, 0, 0, 0, plusTwo)
	offsetVariant.ExpiresAt = time.Date(2026, time.September, 24, 14, 1, 0, 0, plusTwo)
	if !offsetVariant.IssuedAt.Equal(envelope.IssuedAt) || !offsetVariant.ExpiresAt.Equal(envelope.ExpiresAt) {
		t.Fatal("test timestamp offset variant changed the represented instant")
	}
	if _, err := VerifyCurrent(offsetVariant, testScope(), keys, now, policy); !errors.Is(err, ErrInvalid) {
		t.Fatalf("VerifyCurrent() with non-UTC timestamps = %v, want ErrInvalid", err)
	}
	if _, err := Fingerprint(offsetVariant); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Fingerprint() with non-UTC timestamps = %v, want ErrInvalid", err)
	}
	wire, err := json.Marshal(offsetVariant, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEnvelope(wire); !errors.Is(err, ErrInvalid) {
		t.Fatalf("DecodeEnvelope() with non-UTC timestamps = %v, want ErrInvalid", err)
	}
}

func TestVerifyHistoricalDoesNotAuthorizeCurrentAction(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	envelope, err := Sign([]byte(`{"result":"created"}`), testScope(), issued, issued.Add(time.Minute), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keys := testKeyring(t, publicKey)
	if _, err := VerifyHistorical(envelope, testScope(), keys, testPolicy()); err != nil {
		t.Fatalf("VerifyHistorical() error = %v", err)
	}
	if _, err := VerifyCurrent(envelope, testScope(), keys, issued.Add(time.Minute), testPolicy()); !errors.Is(err, ErrExpired) {
		t.Fatalf("VerifyCurrent() after expiry = %v, want ErrExpired", err)
	}
}

func TestDelegationRestrictsPurposeCellRoleAndSlot(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegatePublic, delegatePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegateID, err := KeyID(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := EncodeDelegatedPublicKey(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	delegation := Delegation{
		SchemaVersion:    SchemaVersion,
		SubjectKeyID:     delegateID,
		SubjectPublicKey: encodedPublic,
		Capabilities: []Capability{{
			Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: "deployment-7", Cell: "GRU",
			Environment: "production", Role: "controller", Slots: []string{"controller-1", "controller-2"}, Actions: []string{"sign"},
		}},
	}
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	delegationEnvelope, err := SignDelegation(delegation, now, now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatalf("SignDelegation() error = %v", err)
	}
	verifiedDelegation, err := VerifyDelegationCurrent(delegationEnvelope, testKeyring(t, rootPublic), now, Policy{MaxLifetime: 2 * time.Hour})
	if err != nil {
		t.Fatalf("VerifyDelegationCurrent() error = %v", err)
	}
	allowedScope := Scope{Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: "deployment-7", Cell: "GRU", Environment: "production", Role: "controller", Slot: "controller-1"}
	leaf, err := Sign([]byte(`{"instance":"ocid1.instance"}`), allowedScope, now, now.Add(10*time.Minute), delegatePrivate)
	if err != nil {
		t.Fatalf("Sign(leaf) error = %v", err)
	}
	if _, err := VerifyDelegatedCurrent(leaf, allowedScope, verifiedDelegation, now, testPolicy()); err != nil {
		t.Fatalf("VerifyDelegatedCurrent(allowed) error = %v", err)
	}
	for _, denied := range []Scope{
		{Domain: "terrascale.bootstrap.seed-receipt", DeploymentID: "deployment-7", Cell: "GRU", Environment: "production", Role: "controller", Slot: "controller-1"},
		{Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: "deployment-7", Cell: "SFO", Environment: "production", Role: "controller", Slot: "controller-1"},
		{Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: "deployment-7", Cell: "GRU", Environment: "production", Role: "operator", Slot: "controller-1"},
		{Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: "deployment-7", Cell: "GRU", Environment: "production", Role: "controller", Slot: "controller-3"},
	} {
		if _, err := VerifyDelegatedCurrent(leaf, denied, verifiedDelegation, now, testPolicy()); !errors.Is(err, ErrCapabilityDenied) {
			t.Errorf("VerifyDelegatedCurrent(%s) = %v, want ErrCapabilityDenied", denied, err)
		}
	}
}

func TestHistoricalDelegatedRecordCanBeAuditedButNotUsedCurrently(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegatePublic, delegatePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegateID, _ := KeyID(delegatePublic)
	encodedPublic, _ := EncodeDelegatedPublicKey(delegatePublic)
	delegation := Delegation{SchemaVersion: SchemaVersion, SubjectKeyID: delegateID, SubjectPublicKey: encodedPublic,
		Capabilities: []Capability{{Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: "deployment-7", Cell: "GRU", Environment: "production", Role: "controller", Slots: []string{"controller-1"}, Actions: []string{"sign"}}}}
	issued := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	delegationEnvelope, err := SignDelegation(delegation, issued, issued.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verifiedHistoricalDelegation, err := VerifyDelegationHistorical(delegationEnvelope, testKeyring(t, rootPublic), Policy{MaxLifetime: 2 * time.Hour})
	if err != nil {
		t.Fatalf("VerifyDelegationHistorical() error = %v", err)
	}
	scope := Scope{Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: "deployment-7", Cell: "GRU", Environment: "production", Role: "controller", Slot: "controller-1"}
	leaf, err := Sign([]byte(`{"instance":"ocid1.instance"}`), scope, issued.Add(time.Minute), issued.Add(2*time.Minute), delegatePrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDelegatedHistorical(leaf, scope, verifiedHistoricalDelegation, testPolicy()); err != nil {
		t.Fatalf("VerifyDelegatedHistorical() error = %v", err)
	}
	if _, err := VerifyDelegatedCurrent(leaf, scope, verifiedHistoricalDelegation, issued.Add(2*time.Hour), testPolicy()); !errors.Is(err, ErrExpired) {
		t.Fatalf("VerifyDelegatedCurrent() after delegation expiry = %v, want ErrExpired", err)
	}
}

func TestSignRejectsDuplicatePayloadMembers(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := Sign([]byte(`{"scope":"bootstrap","scope":"release"}`), testScope(), now, now.Add(time.Minute), privateKey); err == nil {
		t.Fatal("Sign() accepted duplicate payload member names")
	}
	if _, err := Sign(jsontext.Value(`{"one":1}`), testScope(), now, now.Add(time.Minute), privateKey); err != nil {
		t.Fatalf("Sign() with JSON value bytes = %v", err)
	}
}

func testScope() Scope {
	return Scope{Domain: "terrascale.bootstrap.manifest", DeploymentID: "deployment-7", Cell: "GRU", Environment: "production", Role: "controller", Slot: "controller-1"}
}

func testScopeWithCell(cell string) Scope {
	scope := testScope()
	scope.Cell = cell
	return scope
}

func testPolicy() Policy { return Policy{MaxLifetime: time.Hour, ClockSkew: 30 * time.Second} }

func testKeyring(t *testing.T, publicKey ed25519.PublicKey) Keyring {
	t.Helper()
	keyring, err := ParseKeyring(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func mustEncode(t *testing.T, envelope Envelope) []byte {
	t.Helper()
	encoded, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
