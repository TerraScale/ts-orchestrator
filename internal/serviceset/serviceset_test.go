package serviceset

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
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
	f := fixture{id: Identity{DeploymentID: "terrascale-prod", Cell: "gru", Environment: "production"},
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

// craft signs payload without the checks of Sign so verification is the
// only gate.
func craft(t *testing.T, payload []byte, scope trust.Scope, lifetime time.Duration, signer ed25519.PrivateKey,
	delegation []byte,
) []byte {
	t.Helper()
	envelope, err := trust.Sign(payload, scope, testNow, testNow.Add(lifetime), signer)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(Signed{Delegation: delegation, Set: encodeEnvelope(t, envelope)})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func rawPayload(t *testing.T, set Set) []byte {
	t.Helper()
	payload, err := trust.EncodePayload(set)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func testSet(id Identity, generation uint64) Set {
	return Set{Schema: Schema, Identity: id, Generation: generation, Services: []Service{
		{Role: "api", Profile: Profile{Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30},
			Args: []string{"--port", "8080"}, Env: map[string]string{"MODE": "api"}}},
		{Role: "web", Profile: Profile{Resources: placement.Resources{CPU: 2, MemoryBytes: 2 << 30, DiskBytes: 1 << 30}},
			Spec: &workload.ServiceSpec{Role: "web", Environment: "production", Kind: workload.KindStateless,
				Replicas: workload.ReplicaBounds{Min: 1, Max: 3}}},
	}}
}

func mustDigest(t *testing.T, set Set) string {
	t.Helper()
	digest, err := Digest(set)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestSignVerifyRoundTripAndExpiry(t *testing.T) {
	f := newFixture(t)
	set := testSet(f.id, 1)
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
		if mustDigest(t, got) != want {
			t.Fatal("verified set differs from the signed set")
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
	if mustDigest(t, got) != want {
		t.Fatal("historical set differs from the signed set")
	}
}

func TestVerifyRejects(t *testing.T) {
	f := newFixture(t)
	scope := f.id.Scope()
	valid := rawPayload(t, testSet(f.id, 1))
	otherPublic, otherPrivate := generateKey(t)
	otherRoots, err := trust.ParseKeyring(otherPublic)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(testSet(f.id, 1), f.delegation, f.roots, testNow, time.Hour, f.leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	withSet := func(set Set) []byte {
		return craft(t, rawPayload(t, set), scope, time.Hour, f.leafPrivate, f.delegation)
	}
	unsorted := testSet(f.id, 1)
	slices.Reverse(unsorted.Services)
	repeated := testSet(f.id, 1)
	repeated.Services[1] = repeated.Services[0]
	wrongSpec := testSet(f.id, 1)
	wrongSpec.Services[1].Spec.Role = "api"
	unsortedReleasers := testSet(f.id, 1)
	unsortedReleasers.Services[0].Releasers = []string{"ops", "ci"}
	invalidReleaser := testSet(f.id, 1)
	invalidReleaser.Services[0].Releasers = []string{"Ops"}
	otherDeployment, otherCell, otherEnvironment := f.id, f.id, f.id
	otherDeployment.DeploymentID = "terrascale-other"
	otherCell.Cell = "sfo"
	otherEnvironment.Environment = "canary"

	cases := []struct {
		name  string
		wire  []byte
		roots trust.Keyring
		want  error
	}{
		{"root signs without delegation", craft(t, valid, scope, time.Hour, f.rootPrivate, f.delegation), nil, trust.ErrUntrustedKey},
		{"delegation for another deployment", craft(t, valid, scope, time.Hour, f.leafPrivate, f.delegationFor(t, otherDeployment)), nil, trust.ErrCapabilityDenied},
		{"delegation for another cell", craft(t, valid, scope, time.Hour, f.leafPrivate, f.delegationFor(t, otherCell)), nil, trust.ErrCapabilityDenied},
		{"delegation for another environment", craft(t, valid, scope, time.Hour, f.leafPrivate, f.delegationFor(t, otherEnvironment)), nil, trust.ErrCapabilityDenied},
		{"tampered set payload", tamper(t, signed), nil, trust.ErrBadSignature},
		{"unknown root", signed, otherRoots, trust.ErrUntrustedKey},
		{"leaf signs for another root", craft(t, valid, scope, time.Hour, f.leafPrivate, delegationSignedBy(t, f, otherPrivate, MaxDelegationLifetime)), nil, trust.ErrUntrustedKey},
		{"non-canonical set payload", craft(t, reorder(t, valid), scope, time.Hour, f.leafPrivate, f.delegation), nil, ErrInvalid},
		{"generation 0", withSet(testSet(f.id, 0)), nil, ErrInvalid},
		{"set lifetime above maximum", craft(t, valid, scope, MaxSetLifetime+time.Second, f.leafPrivate, f.delegation), nil, trust.ErrInvalid},
		{"delegation lifetime above maximum", craft(t, valid, scope, time.Hour, f.leafPrivate, delegationSignedBy(t, f, f.rootPrivate, MaxDelegationLifetime+time.Second)), nil, trust.ErrInvalid},
		{"unsorted roles", withSet(unsorted), nil, ErrInvalid},
		{"repeated roles", withSet(repeated), nil, ErrInvalid},
		{"spec for another role", withSet(wrongSpec), nil, ErrInvalid},
		{"unsorted releasers", withSet(unsortedReleasers), nil, ErrInvalid},
		{"invalid releaser", withSet(invalidReleaser), nil, ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			roots := tc.roots
			if roots == nil {
				roots = f.roots
			}
			for _, verify := range []func() (Set, error){
				func() (Set, error) { return VerifyCurrent(tc.wire, roots, f.id, testNow) },
				func() (Set, error) { return VerifyHistorical(tc.wire, roots, f.id) },
			} {
				_, err := verify()
				if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
					t.Fatalf("verify = %v, want %v", err, tc.want)
				}
			}
		})
	}
}

func TestVerifyRejectsNonCanonicalSignedEncoding(t *testing.T) {
	f := newFixture(t)
	wire, err := Sign(testSet(f.id, 1), f.delegation, f.roots, testNow, time.Hour, f.leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoded := range [][]byte{append([]byte(" "), wire...), bytes.Replace(wire, []byte(`{"delegation":`), []byte(`{"delegation": `), 1)} {
		if _, err := VerifyCurrent(encoded, f.roots, f.id, testNow); !errors.Is(err, ErrInvalid) {
			t.Fatalf("VerifyCurrent(%.40q) = %v, want ErrInvalid", encoded, err)
		}
	}
}

func TestSignRejects(t *testing.T) {
	f := newFixture(t)
	unsorted := testSet(f.id, 1)
	slices.Reverse(unsorted.Services)
	cases := []struct {
		name     string
		set      Set
		validFor time.Duration
	}{
		{"generation 0", testSet(f.id, 0), time.Hour},
		{"zero validity", testSet(f.id, 1), 0},
		{"validity above maximum", testSet(f.id, 1), MaxSetLifetime + time.Second},
		{"unsorted roles", unsorted, time.Hour},
		{"identity outside the delegation", testSet(Identity{DeploymentID: "terrascale-prod", Cell: "fra", Environment: "production"}, 1), time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Sign(tc.set, f.delegation, f.roots, testNow, tc.validFor, f.leafPrivate); err == nil {
				t.Fatal("Sign accepted an invalid set")
			}
		})
	}
	if _, err := SignDelegation(f.leafPublic, f.id, testNow, testNow.Add(MaxDelegationLifetime+time.Second), f.rootPrivate); err == nil {
		t.Fatal("SignDelegation accepted a lifetime above the maximum")
	}
}

func TestDecodeRejectsNonCanonicalSet(t *testing.T) {
	f := newFixture(t)
	canonical, err := Encode(testSet(f.id, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(canonical); err != nil {
		t.Fatal(err)
	}
	for _, encoded := range [][]byte{reorder(t, canonical), append(bytes.Clone(canonical), '\n')} {
		if _, err := Decode(encoded); err == nil {
			t.Fatalf("Decode accepted %q", encoded)
		}
	}
}

func TestDiff(t *testing.T) {
	id := Identity{DeploymentID: "terrascale-prod", Cell: "gru", Environment: "production"}
	current := testSet(id, 1)
	next := testSet(id, 2)
	next.Services[0].Profile.Args = []string{"--port", "9090"}
	next.Services[1] = Service{Role: "db", Profile: current.Services[0].Profile}
	slices.SortFunc(next.Services, func(a, b Service) int { return bytes.Compare([]byte(a.Role), []byte(b.Role)) })
	plan, err := Diff(current, next)
	if err != nil {
		t.Fatal(err)
	}
	if plan.From != 1 || plan.To != 2 || plan.Identity != id || plan.Empty() ||
		!slices.Equal(plan.Added, []string{"db"}) || !slices.Equal(plan.Updated, []string{"api"}) ||
		!slices.Equal(plan.Removed, []string{"web"}) {
		t.Fatalf("Diff = %+v", plan)
	}
	same, err := Diff(current, testSet(id, 1))
	if err != nil {
		t.Fatal(err)
	}
	if !same.Empty() {
		t.Fatalf("Diff of identical sets = %+v", same)
	}
}

// tamper changes the signed generation inside a valid set envelope.
func tamper(t *testing.T, wire []byte) []byte {
	t.Helper()
	var signed Signed
	if err := protocol.DecodeStrict(wire, &signed, MaxSignedBytes); err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(signed.Set)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(envelope.Payload, []byte(`"generation":1`), []byte(`"generation":2`), 1)
	if bytes.Equal(changed, envelope.Payload) {
		t.Fatal("payload has no generation to tamper with")
	}
	envelope.Payload = changed
	signed.Set = encodeEnvelope(t, envelope)
	tampered, err := protocol.EncodeJSON(signed)
	if err != nil {
		t.Fatal(err)
	}
	return tampered
}

// reorder re-encodes a JSON object with its members sorted by name, which
// differs from the set's field order.
func reorder(t *testing.T, payload []byte) []byte {
	t.Helper()
	var members map[string]jsontext.Value
	if err := json.Unmarshal(payload, &members); err != nil {
		t.Fatal(err)
	}
	reordered, err := protocol.EncodeJSON(members)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reordered, payload) {
		t.Fatal("reordering left the payload unchanged")
	}
	return reordered
}

// delegationSignedBy builds the service set grant directly so its signer and
// lifetime bypass SignDelegation's checks.
func delegationSignedBy(t *testing.T, f fixture, signer ed25519.PrivateKey, lifetime time.Duration) []byte {
	t.Helper()
	keyID, err := trust.KeyID(f.leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(f.leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	scope := f.id.Scope()
	envelope, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID,
		SubjectPublicKey: encoded, Capabilities: []trust.Capability{{Domain: scope.Domain,
			DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment,
			Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}},
		testNow.Add(-time.Minute), testNow.Add(-time.Minute+lifetime), signer)
	if err != nil {
		t.Fatal(err)
	}
	return encodeEnvelope(t, envelope)
}

// Host grants are sorted by node, each with one distinct private IPv4
// address, sorted roles and an environment; a plan names every node whose
// grant changes.
func TestHostGrantsValidateAndDiff(t *testing.T) {
	id := Identity{DeploymentID: "terrascale-gru", Cell: "gru", Environment: "canary"}
	grant := func(node, ip string, roles ...string) HostGrant {
		return HostGrant{Node: node, PrivateIP: ip, Roles: roles, Environment: "canary"}
	}
	valid := testSet(id, 1)
	valid.HostGrants = []HostGrant{grant("gru-1-ctl-1", "10.251.0.11", "api"), grant("gru-1-ctl-2", "10.251.0.12", "api", "web")}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid grants: %v", err)
	}
	for name, grants := range map[string][]HostGrant{
		"unsorted":       {valid.HostGrants[1], valid.HostGrants[0]},
		"repeated node":  {valid.HostGrants[0], valid.HostGrants[0]},
		"shared address": {grant("gru-1-ctl-1", "10.251.0.11", "api"), grant("gru-1-ctl-2", "10.251.0.11", "api")},
		"public address": {grant("gru-1-ctl-1", "203.0.113.5", "api")},
		"IPv6 address":   {grant("gru-1-ctl-1", "fd00::1", "api")},
		"no roles":       {grant("gru-1-ctl-1", "10.251.0.11")},
		"unsorted roles": {grant("gru-1-ctl-1", "10.251.0.11", "web", "api")},
		"no environment": {{Node: "gru-1-ctl-1", PrivateIP: "10.251.0.11", Roles: []string{"api"}}},
		"invalid node":   {grant("Gru-1-ctl-1", "10.251.0.11", "api")},
	} {
		invalid := testSet(id, 1)
		invalid.HostGrants = grants
		if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	next := valid
	next.Generation = 2
	next.HostGrants = []HostGrant{grant("gru-1-ctl-2", "10.251.0.12", "web"), grant("gru-1-ctl-3", "10.251.0.13", "api")}
	plan, err := Diff(valid, next)
	if err != nil || plan.Empty() || !slices.Equal(plan.HostGrants, []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"}) ||
		len(plan.Added)+len(plan.Updated)+len(plan.Removed) != 0 {
		t.Fatalf("Diff = %+v, %v", plan, err)
	}
}
