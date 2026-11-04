package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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
	if _, err := VerifyCurrent(decoded, testScopeWithCell("SJC"), testKeyring(t, rootPublic), now, testPolicy()); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("wrong-cell verification error = %v, want ErrScopeMismatch", err)
	}
	if _, err := VerifyCurrent(decoded, scope, testKeyring(t, rootPublic), now.Add(time.Minute), testPolicy()); !errors.Is(err, ErrExpired) {
		t.Fatalf("at-expiry verification error = %v, want ErrExpired", err)
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
			Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: "0000000000KAHFE3RAB6316KW8", Cell: "GRU",
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
	allowedScope := Scope{Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: "0000000000KAHFE3RAB6316KW8", Cell: "GRU", Environment: "production", Role: "controller", Slot: "controller-1"}
	leaf, err := Sign([]byte(`{"instance":"ocid1.instance"}`), allowedScope, now, now.Add(10*time.Minute), delegatePrivate)
	if err != nil {
		t.Fatalf("Sign(leaf) error = %v", err)
	}
	if _, err := VerifyDelegatedCurrent(leaf, allowedScope, verifiedDelegation, now, testPolicy()); err != nil {
		t.Fatalf("VerifyDelegatedCurrent(allowed) error = %v", err)
	}
	for _, denied := range []Scope{
		{Domain: "terrascale.bootstrap.seed-receipt", DeploymentID: "0000000000KAHFE3RAB6316KW8", Cell: "GRU", Environment: "production", Role: "controller", Slot: "controller-1"},
	} {
		if _, err := VerifyDelegatedCurrent(leaf, denied, verifiedDelegation, now, testPolicy()); !errors.Is(err, ErrCapabilityDenied) {
			t.Errorf("VerifyDelegatedCurrent(%s) = %v, want ErrCapabilityDenied", denied, err)
		}
	}
}

func testScope() Scope {
	return Scope{Domain: "terrascale.bootstrap.manifest", DeploymentID: "0000000000KAHFE3RAB6316KW8", Cell: "GRU", Environment: "production", Role: "controller", Slot: "controller-1"}
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
