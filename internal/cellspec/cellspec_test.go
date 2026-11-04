package cellspec

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

var testNow = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

type fixture struct {
	id          Identity
	rootPrivate ed25519.PrivateKey
	leafPublic  ed25519.PublicKey
	leafPrivate ed25519.PrivateKey
	roots       trust.Keyring
	delegation  []byte
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	rootPublic, rootPrivate := generateKey(t)
	leafPublic, leafPrivate := generateKey(t)
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{id: Identity{DeploymentID: "0000000000VVK5ZNRRNEED4PH3", Cell: "gru", Environment: "production"},
		rootPrivate: rootPrivate, leafPublic: leafPublic, leafPrivate: leafPrivate, roots: roots}
	f.delegation = f.delegationFor(t, f.id)
	return f
}

func generateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func (f fixture) delegationFor(t *testing.T, id Identity) []byte {
	t.Helper()
	envelope, err := SignDelegation(f.leafPublic, id, testNow.Add(-time.Minute), testNow.Add(7*24*time.Hour), f.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return encodeEnvelope(t, envelope)
}

func encodeEnvelope(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func testSpec(id Identity, generation uint64) Spec {
	return Spec{Schema: Schema, Identity: id, Generation: generation, RequiresBinary: 1, Services: []Service{
		{Role: "api", Profile: Profile{Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30},
			Args: []string{"--port", "8080"}, Env: map[string]string{"MODE": "api"}}},
		{Role: "web", Profile: Profile{Resources: placement.Resources{CPU: 2, MemoryBytes: 2 << 30, DiskBytes: 1 << 30}},
			Spec: &workload.ServiceSpec{Role: "web", Environment: "production", Kind: workload.KindStateless,
				Replicas: workload.ReplicaBounds{Min: 1, Max: 3}}},
	}}
}

func mustDigest(t *testing.T, set Spec) string {
	t.Helper()
	digest, err := Digest(set)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestSignVerifyRoundTripAndExpiry(t *testing.T) {
	f := newFixture(t)
	set := testSpec(f.id, 1)
	wire, err := Sign(set, f.delegation, f.roots, testNow, time.Hour, f.leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	want := mustDigest(t, set)
	for _, now := range []time.Time{testNow, testNow.Add(59 * time.Minute)} {
		got, err := VerifyCurrent(wire, f.roots, f.id, now)
		if err != nil {
			t.Fatalf("VerifyCurrent at %s: %v", now, err)
		}
		if mustDigest(t, got.Spec) != want {
			t.Fatal("verified spec differs from the signed spec")
		}
	}
	for _, now := range []time.Time{testNow.Add(time.Hour), testNow.Add(8 * 24 * time.Hour)} {
		if _, err := VerifyCurrent(wire, f.roots, f.id, now); !errors.Is(err, trust.ErrExpired) {
			t.Fatalf("VerifyCurrent at %s = %v, want expiry", now, err)
		}
	}
	got, err := VerifyHistorical(wire, f.roots, f.id)
	if err != nil {
		t.Fatalf("VerifyHistorical after expiry: %v", err)
	}
	if mustDigest(t, got.Spec) != want {
		t.Fatal("historical spec differs from the signed spec")
	}
}

func TestVerifyRejects(t *testing.T) {
	f := newFixture(t)
	signed, err := Sign(testSpec(f.id, 1), f.delegation, f.roots, testNow, time.Hour, f.leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyCurrent(tamper(t, signed), f.roots, f.id, testNow)
	if !errors.Is(err, trust.ErrBadSignature) {
		t.Fatalf("tampered spec: %v", err)
	}
}

// tamper changes the signed generation inside a valid spec envelope.
func tamper(t *testing.T, wire []byte) []byte {
	t.Helper()
	var signed Signed
	if err := protocol.DecodeStrict(wire, &signed, MaxSignedBytes); err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(signed.Spec)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(envelope.Payload, []byte(`"generation":1`), []byte(`"generation":2`), 1)
	if bytes.Equal(changed, envelope.Payload) {
		t.Fatal("payload has no generation to tamper with")
	}
	envelope.Payload = changed
	signed.Spec = encodeEnvelope(t, envelope)
	tampered, err := protocol.EncodeJSON(signed)
	if err != nil {
		t.Fatal(err)
	}
	return tampered
}
