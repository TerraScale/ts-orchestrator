package cellspec

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostpool"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/bucket"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
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
	wire, err := protocol.EncodeJSON(Signed{Delegation: delegation, Spec: encodeEnvelope(t, envelope)})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func rawPayload(t *testing.T, set Spec) []byte {
	t.Helper()
	payload, err := trust.EncodePayload(set)
	if err != nil {
		t.Fatal(err)
	}
	return payload
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
	scope := f.id.Scope()
	valid := rawPayload(t, testSpec(f.id, 1))
	otherPublic, otherPrivate := generateKey(t)
	otherRoots, err := trust.ParseKeyring(otherPublic)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(testSpec(f.id, 1), f.delegation, f.roots, testNow, time.Hour, f.leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	withSet := func(set Spec) []byte {
		return craft(t, rawPayload(t, set), scope, time.Hour, f.leafPrivate, f.delegation)
	}
	unsorted := testSpec(f.id, 1)
	slices.Reverse(unsorted.Services)
	repeated := testSpec(f.id, 1)
	repeated.Services[1] = repeated.Services[0]
	wrongSpec := testSpec(f.id, 1)
	wrongSpec.Services[1].Spec.Role = "api"
	unsortedReleasers := testSpec(f.id, 1)
	unsortedReleasers.Services[0].Releasers = []string{"ops", "ci"}
	invalidReleaser := testSpec(f.id, 1)
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
		{"tampered spec payload", tamper(t, signed), nil, trust.ErrBadSignature},
		{"unknown root", signed, otherRoots, trust.ErrUntrustedKey},
		{"leaf signs for another root", craft(t, valid, scope, time.Hour, f.leafPrivate, delegationSignedBy(t, f, otherPrivate, MaxDelegationLifetime)), nil, trust.ErrUntrustedKey},
		{"non-canonical spec payload", craft(t, reorder(t, valid), scope, time.Hour, f.leafPrivate, f.delegation), nil, ErrInvalid},
		{"generation 0", withSet(testSpec(f.id, 0)), nil, ErrInvalid},
		{"spec lifetime above maximum", craft(t, valid, scope, MaxSpecLifetime+time.Second, f.leafPrivate, f.delegation), nil, trust.ErrInvalid},
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
			for _, verify := range []func() (Verified, error){
				func() (Verified, error) { return VerifyCurrent(tc.wire, roots, f.id, testNow) },
				func() (Verified, error) { return VerifyHistorical(tc.wire, roots, f.id) },
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
	wire, err := Sign(testSpec(f.id, 1), f.delegation, f.roots, testNow, time.Hour, f.leafPrivate)
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
	unsorted := testSpec(f.id, 1)
	slices.Reverse(unsorted.Services)
	cases := []struct {
		name     string
		set      Spec
		validFor time.Duration
	}{
		{"generation 0", testSpec(f.id, 0), time.Hour},
		{"zero validity", testSpec(f.id, 1), 0},
		{"validity above maximum", testSpec(f.id, 1), MaxSpecLifetime + time.Second},
		{"unsorted roles", unsorted, time.Hour},
		{"identity outside the delegation", testSpec(Identity{DeploymentID: "terrascale-prod", Cell: "fra", Environment: "production"}, 1), time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Sign(tc.set, f.delegation, f.roots, testNow, tc.validFor, f.leafPrivate); err == nil {
				t.Fatal("Sign accepted an invalid spec")
			}
		})
	}
	if _, err := SignDelegation(f.leafPublic, f.id, testNow, testNow.Add(MaxDelegationLifetime+time.Second), f.rootPrivate); err == nil {
		t.Fatal("SignDelegation accepted a lifetime above the maximum")
	}
}

func TestDecodeRejectsNonCanonicalSpec(t *testing.T) {
	f := newFixture(t)
	canonical, err := Encode(testSpec(f.id, 1))
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
	current := testSpec(id, 1)
	next := testSpec(id, 2)
	next.Services[0].Profile.Args = []string{"--port", "9090"}
	next.Services[1] = Service{Role: "db", Profile: current.Services[0].Profile}
	slices.SortFunc(next.Services, func(a, b Service) int { return bytes.Compare([]byte(a.Role), []byte(b.Role)) })
	plan, err := Diff(current, next, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.From != 1 || plan.To != 2 || plan.Identity != id || plan.Empty() ||
		!slices.Equal(plan.Added, []string{"db"}) || !slices.Equal(plan.Updated, []string{"api"}) ||
		!slices.Equal(plan.Removed, []string{"web"}) {
		t.Fatalf("Diff = %+v", plan)
	}
	same, err := Diff(current, testSpec(id, 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !same.Empty() {
		t.Fatalf("Diff of identical specs = %+v", same)
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

// reorder re-encodes a JSON object with its members sorted by name, which
// differs from the spec's field order.
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

// delegationSignedBy builds the cell spec grant directly so its signer and
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

// A root signs an authority-widening amendment itself, without a
// delegation; no other key can stand in for it.
func TestRootSignedSpec(t *testing.T) {
	f := newFixture(t)
	spec := testSpec(f.id, 1)
	wire, err := Sign(spec, nil, f.roots, testNow, time.Hour, f.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	for _, verify := range []func() (Verified, error){
		func() (Verified, error) { return VerifyCurrent(wire, f.roots, f.id, testNow) },
		func() (Verified, error) { return VerifyHistorical(wire, f.roots, f.id) },
	} {
		got, err := verify()
		if err != nil || !got.RootSigned || mustDigest(t, got.Spec) != mustDigest(t, spec) {
			t.Fatalf("root-signed spec: %+v, %v", got, err)
		}
	}
	leafSigned, err := Sign(spec, f.delegation, f.roots, testNow, time.Hour, f.leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyCurrent(leafSigned, f.roots, f.id, testNow); err != nil || got.RootSigned {
		t.Fatalf("leaf-signed spec: %+v, %v", got, err)
	}
	if _, err := VerifyCurrent(wire, f.roots, f.id, testNow.Add(time.Hour)); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired root-signed spec = %v", err)
	}
	if _, err := Sign(spec, nil, f.roots, testNow, time.Hour, f.leafPrivate); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("the leaf signed as a root: %v", err)
	}
	// Dropping the delegation from a leaf-signed spec does not make it a
	// root's.
	var signed Signed
	if err := protocol.DecodeStrict(leafSigned, &signed, MaxSignedBytes); err != nil {
		t.Fatal(err)
	}
	stripped, err := protocol.EncodeJSON(Signed{Spec: signed.Spec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHistorical(stripped, f.roots, f.id); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("a leaf-signed spec without its delegation = %v", err)
	}
	if _, err := VerifyHistorical(tamper(t, wire), f.roots, f.id); !errors.Is(err, trust.ErrBadSignature) {
		t.Fatalf("tampered root-signed spec = %v", err)
	}
}

// An amendment for a newer binary is refused by name, before its sections
// are read; an unknown section under this binary's level is invalid.
func TestNewerBinaryAndUnknownSections(t *testing.T) {
	f := newFixture(t)
	payload := rawPayload(t, testSpec(f.id, 1))
	newer := bytes.Replace(payload, []byte(`"requires_binary":1`), []byte(fmt.Sprintf(`"requires_binary":%d`, BinaryLevel+1)), 1)
	newer = bytes.Replace(newer, []byte(`"services":`), []byte(`"edge":{"records":[]},"services":`), 1)
	unknown := bytes.Replace(payload, []byte(`"services":`), []byte(`"edge":{"records":[]},"services":`), 1)
	var refused *NewerBinaryError
	if _, err := Decode(newer); !errors.As(err, &refused) || refused.Generation != 1 || refused.RequiresBinary != BinaryLevel+1 {
		t.Fatalf("Decode(newer) = %v", err)
	}
	if _, err := VerifyHistorical(craft(t, newer, f.id.Scope(), time.Hour, f.leafPrivate, f.delegation), f.roots, f.id); !errors.As(err, &refused) {
		t.Fatalf("VerifyHistorical(newer) = %v", err)
	}
	if _, err := Decode(unknown); !errors.Is(err, ErrInvalid) || errors.As(err, &refused) {
		t.Fatalf("Decode(unknown section) = %v", err)
	}
	for _, level := range []uint64{0, BinaryLevel + 1} {
		spec := testSpec(f.id, 1)
		spec.RequiresBinary = level
		if _, err := Encode(spec); !errors.Is(err, ErrInvalid) {
			t.Errorf("Encode(requires_binary %d) = %v", level, err)
		}
	}
}

func TestCandidateReadsUnsignedAndSignedFiles(t *testing.T) {
	f := newFixture(t)
	spec := testSpec(f.id, 1)
	unsigned, err := Encode(spec)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(spec, f.delegation, f.roots, testNow, time.Hour, f.leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{unsigned, signed} {
		if got, err := Candidate(data); err != nil || mustDigest(t, got) != mustDigest(t, spec) {
			t.Fatalf("Candidate = %+v, %v", got, err)
		}
	}
	if _, err := Candidate([]byte(`{"spec":"x"}`)); err == nil {
		t.Fatal("Candidate accepted a broken signed file")
	}
}

func TestAuthorityChanges(t *testing.T) {
	id := Identity{DeploymentID: "terrascale-prod", Cell: "gru", Environment: "production"}
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	signed := map[string]Profile{terrabase.Role: {Resources: resources, Args: []string{"--serve"},
		Env: map[string]string{"TERRABASE_REGION": "gru-1", terrabase.EnvPeerPort: "9443",
			terrabase.EnvPeers: "gru-1-db-1=10.251.0.21:9443"}}}
	with := func(generation uint64, services ...Service) Spec {
		return Spec{Schema: Schema, Identity: id, Generation: generation, RequiresBinary: 1, Services: services}
	}
	tb := func(change func(*Profile)) Service {
		profile := signed[terrabase.Role]
		profile.Args = slices.Clone(profile.Args)
		profile.Env = maps.Clone(profile.Env)
		change(&profile)
		return Service{Role: terrabase.Role, Profile: profile}
	}
	web := Service{Role: "web", Profile: Profile{Resources: resources}}
	released := web
	released.Releasers = []string{"ci", "ops"}
	issuer := tb(func(p *Profile) { p.Env["TERRABASE_AUTH_ISSUER"] = "https://gru.auth.terrascale.tech/terrascale" })
	vault := "ocid1.vault.oc1.sa-saopaulo-1.vault"
	withSecrets := func(refs map[string]vaultsecret.Ref) Service {
		return Service{Role: "web", Profile: Profile{Resources: resources, Secrets: refs}}
	}
	token := withSecrets(map[string]vaultsecret.Ref{"TOKEN": {Vault: vault, Name: "gru-1-web-token"}})
	cases := []struct {
		name          string
		current, next Spec
		want          []string
	}{
		{"new service", with(0), with(1, web), nil},
		{"service profile", with(1, web), with(2, Service{Role: "web", Profile: Profile{Resources: resources, Args: []string{"-v"}}}), nil},
		{"unchanged TerraBase entry", with(1, issuer), with(2, issuer, web), nil},
		{"TerraBase entry equal to the signed profile", with(0), with(1, tb(func(*Profile) {})), nil},
		// Authentication and credentials are authority too.
		{"added TerraBase setting", with(0), with(1, issuer), []string{"terrabase setting TERRABASE_AUTH_ISSUER"}},
		{"changed added setting", with(1, issuer), with(2, tb(func(p *Profile) { p.Env["TERRABASE_AUTH_ISSUER"] = "https://other" })), []string{"terrabase setting TERRABASE_AUTH_ISSUER"}},
		{"dropped TerraBase entry", with(1, issuer), with(2), []string{"terrabase setting TERRABASE_AUTH_ISSUER"}},
		{"preload", with(0), with(1, tb(func(p *Profile) { p.Env["LD_PRELOAD"] = "/tmp/x.so" })), []string{"terrabase setting LD_PRELOAD"}},
		{"dropped releaser", with(1, released), with(2, web), nil},
		// A ref picks the secret and its Vault: only a root adds or changes one.
		{"new secret", with(1, web), with(2, token), []string{"service web Vault secrets"}},
		{"secrets of a new service", with(1), with(2, token), []string{"service web Vault secrets"}},
		{"other Vault", with(1, token), with(2, withSecrets(map[string]vaultsecret.Ref{"TOKEN": {Vault: vault + "x", Name: "gru-1-web-token"}})), []string{"service web Vault secrets"}},
		{"renamed secret", with(1, token), with(2, withSecrets(map[string]vaultsecret.Ref{"TOKEN": {Vault: vault, Name: "gru-1-web-other"}})), []string{"service web Vault secrets"}},
		{"kept secrets", with(1, token), with(2, token), nil},
		{"dropped secrets", with(1, token), with(2, web), nil},
		{"new releasers", with(1, web), with(2, released), []string{"service web releaser ci", "service web releaser ops"}},
		{"releasers of a new service", with(1), with(2, released), []string{"service web releaser ci", "service web releaser ops"}},
		{"TerraBase resources", with(0), with(1, tb(func(p *Profile) { p.Resources.CPU = 2 })), []string{"terrabase resources"}},
		{"TerraBase args", with(0), with(1, tb(func(p *Profile) { p.Args = nil })), []string{"terrabase args"}},
		{"TerraBase peers", with(0), with(1, tb(func(p *Profile) { p.Env[terrabase.EnvPeers] += ",gru-1-db-2=10.251.0.22:9443" })), []string{"terrabase setting " + terrabase.EnvPeers}},
		{"TerraBase peer addresses", with(0), with(1, tb(func(p *Profile) { p.Env["TERRABASE_PEER_ADDRESSES"] = "10.0.0.1" })), []string{"terrabase setting TERRABASE_PEER_ADDRESSES"}},
		{"TerraBase client port", with(0), with(1, tb(func(p *Profile) { p.Env[terrabase.EnvClientPort] = "9465" })), []string{"terrabase setting " + terrabase.EnvClientPort}},
		{"signed setting", with(0), with(1, tb(func(p *Profile) { delete(p.Env, "TERRABASE_REGION") })), []string{"terrabase setting TERRABASE_REGION"}},
		// The leaf keeps what a root widened; reverting it is a change too.
		{"kept root change", with(1, tb(func(p *Profile) { p.Resources.CPU = 2 })), with(2, tb(func(p *Profile) { p.Resources.CPU = 2 }), web), nil},
		{"reverted root change", with(1, tb(func(p *Profile) { p.Resources.CPU = 2 })), with(2), []string{"terrabase resources"}},
	}
	for _, tc := range cases {
		if got := AuthorityChanges(tc.current, tc.next, signed); !slices.Equal(got, tc.want) {
			t.Errorf("%s: AuthorityChanges = %q, want %q", tc.name, got, tc.want)
		}
	}
	plan, err := Diff(with(1, web), with(2, released, tb(func(p *Profile) { p.Args = nil })), signed)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.RootRequired, []string{"service web releaser ci", "service web releaser ops", "terrabase args"}) ||
		!slices.Equal(plan.Added, []string{terrabase.Role}) || !slices.Equal(plan.Updated, []string{"web"}) || plan.RequiresBinary != 1 {
		t.Fatalf("Diff = %+v", plan)
	}
}

// Host grants are sorted by node, each with one distinct private IPv4
// address, sorted roles and an environment; a plan names every node whose
// grant changes, and a new or changed grant needs a root.
func TestHostGrantsValidateDiffAndWiden(t *testing.T) {
	id := Identity{DeploymentID: "terrascale-gru", Cell: "gru", Environment: "canary"}
	grant := func(node, ip string, roles ...string) HostGrant {
		return HostGrant{Node: node, PrivateIP: ip, Roles: roles, Environment: "canary"}
	}
	valid := testSpec(id, 1)
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
		invalid := testSpec(id, 1)
		invalid.HostGrants = grants
		if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	next := valid
	next.Generation = 2
	next.HostGrants = []HostGrant{grant("gru-1-ctl-2", "10.251.0.12", "web"), grant("gru-1-ctl-3", "10.251.0.13", "api")}
	plan, err := Diff(valid, next, nil)
	if err != nil || plan.Empty() || !slices.Equal(plan.HostGrants, []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"}) ||
		len(plan.Added)+len(plan.Updated)+len(plan.Removed) != 0 ||
		!slices.Equal(plan.RootRequired, []string{"host grant gru-1-ctl-2", "host grant gru-1-ctl-3"}) {
		t.Fatalf("Diff = %+v, %v", plan, err)
	}
	// Revoking a grant and keeping one unchanged are ordinary.
	revoked := valid
	revoked.Generation = 2
	revoked.HostGrants = valid.HostGrants[1:]
	if changes := AuthorityChanges(valid, revoked, nil); len(changes) != 0 {
		t.Fatalf("revoking a grant widens %q", changes)
	}
}

// A spec whose profiles name Vault secrets needs binary level 2, so an older
// binary refuses it by name instead of failing to read the new field.
func TestProfileSecretsRequireLevelTwo(t *testing.T) {
	f := newFixture(t)
	spec := testSpec(f.id, 1)
	if spec.Level() != 1 {
		t.Fatalf("level without secrets = %d", spec.Level())
	}
	spec.Services[1].Profile.Secrets = map[string]vaultsecret.Ref{"TOKEN": {Vault: "ocid1.vault.oc1.sa-saopaulo-1.vault", Name: "gru-1-web-token"}}
	if spec.Level() != 2 {
		t.Fatalf("level with secrets = %d", spec.Level())
	}
	if _, err := Encode(spec); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Encode(secrets at level 1) = %v", err)
	}
	spec.RequiresBinary = 2
	payload, err := Encode(spec)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(payload)
	if err != nil || decoded.Services[1].Profile.Secrets["TOKEN"].Name != "gru-1-web-token" {
		t.Fatalf("Decode = %+v, %v", decoded.Services, err)
	}
}

// A budget needs binary level 3. Only a lower cap in the same currency is an
// ordinary amendment: every other budget change lets the cell spend more.
func TestBudgetLevelValidateDiffAndWiden(t *testing.T) {
	f := newFixture(t)
	spec := testSpec(f.id, 1)
	spec.Budget = &hostpool.Budget{MonthlyCapCents: 50000, Currency: "USD"}
	if spec.Level() != 3 {
		t.Fatalf("level with a budget = %d", spec.Level())
	}
	secrets := spec
	secrets.Services = slices.Clone(spec.Services)
	secrets.Services[1].Profile.Secrets = map[string]vaultsecret.Ref{"TOKEN": {Vault: "ocid1.vault.oc1.sa-saopaulo-1.vault", Name: "gru-1-web-token"}}
	if secrets.Level() != 3 {
		t.Fatalf("level with a budget and secrets = %d", secrets.Level())
	}
	if _, err := Encode(spec); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Encode(budget at level 1) = %v", err)
	}
	spec.RequiresBinary = 3
	payload, err := Encode(spec)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := Decode(payload); err != nil || *decoded.Budget != *spec.Budget {
		t.Fatalf("Decode = %+v, %v", decoded.Budget, err)
	}
	invalid := spec
	invalid.Budget = &hostpool.Budget{MonthlyCapCents: 0, Currency: "USD"}
	if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero cap accepted: %v", err)
	}

	unbudgeted := testSpec(f.id, 1)
	for name, test := range map[string]struct {
		before, after *hostpool.Budget
		change        string
		widens        bool
	}{
		"add":             {after: spec.Budget, change: "added", widens: true},
		"remove":          {before: spec.Budget, change: "removed", widens: true},
		"raise":           {before: spec.Budget, after: &hostpool.Budget{MonthlyCapCents: 50001, Currency: "USD"}, change: "updated", widens: true},
		"change currency": {before: spec.Budget, after: &hostpool.Budget{MonthlyCapCents: 100, Currency: "BRL"}, change: "updated", widens: true},
		"lower":           {before: spec.Budget, after: &hostpool.Budget{MonthlyCapCents: 49999, Currency: "USD"}, change: "updated"},
		"keep":            {before: spec.Budget, after: &hostpool.Budget{MonthlyCapCents: 50000, Currency: "USD"}},
	} {
		current, next := unbudgeted, unbudgeted
		current.Budget, next.Budget = test.before, test.after
		next.Generation = 2
		plan, err := Diff(current, next, nil)
		if err != nil || plan.Budget != test.change || plan.Empty() != (test.change == "") ||
			slices.Equal(plan.RootRequired, []string{"budget"}) != test.widens || len(plan.RootRequired) > 1 {
			t.Errorf("%s: Diff = %+v, %v", name, plan, err)
		}
	}
}

const (
	testImageA = "ocid1.image.oc1.sa-saopaulo-1.imagea"
	testImageB = "ocid1.image.oc1.sa-saopaulo-1.imageb"
)

// hostImage signs a release image receipt for imageID in environment with
// the fixture's leaf, under a root delegation for those images, valid from
// testNow for lifetime.
func (f fixture) hostImage(t *testing.T, imageID, environment string, root ed25519.PrivateKey, lifetime time.Duration) HostImage {
	t.Helper()
	keyID, err := trust.KeyID(f.leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	public, err := trust.EncodeDelegatedPublicKey(f.leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	revision := "0123456789abcdef0123456789abcdef01234567"
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID,
		SubjectPublicKey: public, Capabilities: []trust.Capability{{Domain: release.ImageDomain, DeploymentID: revision,
			Cell: "GRU", Environment: environment, Role: "oci-image", Slots: []string{imageID}, Actions: []string{"sign"}}},
	}, testNow.Add(-time.Minute), testNow.Add(lifetime), root)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("ab", 32)
	payload := release.ImageReceipt{
		Schema: release.ImageSchema, SourceRevision: revision, GoVersion: release.DefaultGoVersion,
		Architecture: "arm64", BinaryBytes: 100, BinarySHA256: digest, QualificationSHA256: digest,
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU", BaseImageSHA256: digest,
		KernelRelease: "6.1.0-test+1", KernelSHA256: digest, ImageFormat: "qcow2", ImageBytes: 1024,
		ImageSHA256: digest, OCIImageOCID: imageID, OCIRegion: "GRU",
	}
	receipt, err := release.SignImageReceipt(payload, environment, delegation, f.roots, f.leafPrivate, testNow, lifetime)
	if err != nil && root.Equal(f.rootPrivate) {
		t.Fatal(err)
	}
	if err != nil {
		// SignImageReceipt refuses a delegation from another key; sign the
		// same receipt directly so verification is the only gate.
		encoded, encodeErr := trust.EncodePayload(payload)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		if receipt, err = trust.Sign(encoded, release.ImageScope(payload, environment), testNow, testNow.Add(lifetime), f.leafPrivate); err != nil {
			t.Fatal(err)
		}
	}
	return HostImage{ImageID: imageID, Receipt: encodeEnvelope(t, receipt), Delegation: encodeEnvelope(t, delegation)}
}

func TestHostImagesValidateVerifyAndDiff(t *testing.T) {
	f := newFixture(t)
	imageA := f.hostImage(t, testImageA, "production", f.rootPrivate, time.Hour)
	imageB := f.hostImage(t, testImageB, "production", f.rootPrivate, time.Hour)
	spec := testSpec(f.id, 1)
	spec.HostImages = []HostImage{imageA, imageB}
	if err := spec.Validate(); !errors.Is(err, ErrInvalid) || spec.Level() != 4 {
		t.Fatalf("host images at binary level 1: level %d, %v", spec.Level(), err)
	}
	spec.RequiresBinary = 4
	wire, err := Sign(spec, f.delegation, f.roots, testNow, time.Hour, f.leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyHistorical(wire, f.roots, f.id)
	if err != nil || len(verified.HostImages) != 2 || verified.HostImages[1].ImageID != testImageB {
		t.Fatalf("VerifyHistorical = %+v, %v", verified.HostImages, err)
	}

	tampered := imageA
	tampered.Receipt = bytes.Clone(imageA.Receipt)
	tampered.Receipt[len(tampered.Receipt)-3] ^= 1
	_, otherRootPrivate := generateKey(t)
	for name, images := range map[string][]HostImage{
		"unsorted":         {imageB, imageA},
		"repeated":         {imageA, imageA},
		"foreign region":   {{ImageID: "ocid1.image.oc1.us-sanjose-1.imagea", Receipt: imageA.Receipt, Delegation: imageA.Delegation}},
		"no receipt":       {{ImageID: testImageA, Delegation: imageA.Delegation}},
		"no delegation":    {{ImageID: testImageA, Receipt: imageA.Receipt}},
		"over the maximum": {imageA, imageB, f.hostImage(t, testImageA+"c", "production", f.rootPrivate, time.Hour), f.hostImage(t, testImageA+"d", "production", f.rootPrivate, time.Hour), f.hostImage(t, testImageA+"e", "production", f.rootPrivate, time.Hour)},
	} {
		invalid := testSpec(f.id, 1)
		invalid.RequiresBinary = 4
		invalid.HostImages = images
		if name == "over the maximum" {
			slices.SortFunc(invalid.HostImages, func(a, b HostImage) int { return strings.Compare(a.ImageID, b.ImageID) })
		}
		if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, image := range map[string]HostImage{
		"tampered receipt":      tampered,
		"receipt of another ID": {ImageID: testImageB, Receipt: imageA.Receipt, Delegation: imageA.Delegation},
		"other environment":     f.hostImage(t, testImageA, "canary", f.rootPrivate, time.Hour),
		"delegation not a root": f.hostImage(t, testImageA, "production", otherRootPrivate, time.Hour),
	} {
		unqualified := spec
		unqualified.HostImages = []HostImage{image}
		if err := VerifyHostImages(Spec{}, unqualified, f.roots, nil); err == nil {
			t.Errorf("%s: unqualified host image verified", name)
		}
		if err := VerifyHostImages(Spec{}, unqualified, f.roots, &testNow); err == nil {
			t.Errorf("%s: unqualified host image admitted", name)
		}
	}

	// An accepted image stays allowed after its receipt expires; an added or
	// changed one must be qualified now.
	later := testNow.Add(2 * time.Hour)
	if err := VerifyHostImages(spec, spec, f.roots, &later); err != nil {
		t.Fatalf("kept expired image refused: %v", err)
	}
	if err := VerifyHostImages(Spec{}, spec, f.roots, &later); err == nil {
		t.Fatal("added expired image admitted")
	}
	renewed := spec
	renewed.HostImages = []HostImage{f.hostImage(t, testImageA, "production", f.rootPrivate, 90*time.Minute), imageB}
	if err := VerifyHostImages(spec, renewed, f.roots, &later); err == nil {
		t.Fatal("changed expired image admitted")
	}

	// A root decides that the cell runs an image; revoking one is ordinary.
	next := spec
	next.Generation = 2
	next.HostImages = []HostImage{imageB}
	plan, err := Diff(spec, next, nil)
	if err != nil || plan.Empty() || !slices.Equal(plan.HostImages, []string{testImageA}) || len(plan.RootRequired) != 0 {
		t.Fatalf("Diff(revoke) = %+v, %v", plan, err)
	}
	plan, err = Diff(next, renewed, nil)
	if err != nil || !slices.Equal(plan.HostImages, []string{testImageA}) ||
		!slices.Equal(plan.RootRequired, []string{"host image " + testImageA}) {
		t.Fatalf("Diff(add) = %+v, %v", plan, err)
	}
	plan, err = Diff(spec, renewed, nil)
	if err != nil || !slices.Equal(plan.RootRequired, []string{"host image " + testImageA}) {
		t.Fatalf("Diff(change) = %+v, %v", plan, err)
	}
	if plan, err := Diff(spec, spec, nil); err != nil || !plan.Empty() {
		t.Fatalf("Diff(unchanged) = %+v, %v", plan, err)
	}
}

// A kv_snapshot schedule needs binary level 5. Pausing it needs a root,
// since a rebuilt cell restores only what was uploaded; the interval and
// resuming are ordinary.
func TestKVSnapshotLevelValidateDiffAndWiden(t *testing.T) {
	f := newFixture(t)
	spec := testSpec(f.id, 1)
	spec.KVSnapshot = &KVSnapshot{IntervalSeconds: 60}
	if spec.Level() != 5 {
		t.Fatalf("level with a kv_snapshot schedule = %d", spec.Level())
	}
	if _, err := Encode(spec); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Encode(kv_snapshot at level 1) = %v", err)
	}
	spec.RequiresBinary = 5
	payload, err := Encode(spec)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := Decode(payload); err != nil || *decoded.KVSnapshot != *spec.KVSnapshot {
		t.Fatalf("Decode = %+v, %v", decoded.KVSnapshot, err)
	}
	for _, seconds := range []int{4, 3601, -1} {
		invalid := spec
		invalid.KVSnapshot = &KVSnapshot{IntervalSeconds: seconds}
		if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("interval %d accepted: %v", seconds, err)
		}
	}

	unscheduled := testSpec(f.id, 1)
	paused := &KVSnapshot{Paused: true}
	for name, test := range map[string]struct {
		before, after *KVSnapshot
		change        string
		widens        bool
	}{
		"add interval":  {after: spec.KVSnapshot, change: "added"},
		"add paused":    {after: paused, change: "added", widens: true},
		"pause":         {before: spec.KVSnapshot, after: &KVSnapshot{IntervalSeconds: 60, Paused: true}, change: "updated", widens: true},
		"resume":        {before: paused, after: &KVSnapshot{}, change: "updated"},
		"keep paused":   {before: paused, after: &KVSnapshot{IntervalSeconds: 3600, Paused: true}, change: "updated"},
		"remove paused": {before: paused, change: "removed"},
		"keep":          {before: spec.KVSnapshot, after: &KVSnapshot{IntervalSeconds: 60}},
	} {
		current, next := unscheduled, unscheduled
		current.KVSnapshot, next.KVSnapshot = test.before, test.after
		next.Generation = 2
		plan, err := Diff(current, next, nil)
		if err != nil || plan.KVSnapshot != test.change || plan.Empty() != (test.change == "") ||
			slices.Equal(plan.RootRequired, []string{"kv_snapshot pause"}) != test.widens || len(plan.RootRequired) > 1 {
			t.Errorf("%s: Diff = %+v, %v", name, plan, err)
		}
	}
}

// A rollout policy needs binary level 6 and passes the rollout bounds. It
// widens no authority: a leaf may change it.
func TestRolloutPolicyLevelValidateAndDiff(t *testing.T) {
	f := newFixture(t)
	spec := testSpec(f.id, 1)
	policy := rollout.DefaultPolicy()
	policy.BatchSize = 1
	spec.RolloutPolicy, spec.RequiresBinary = &policy, 6
	if spec.Level() != 6 {
		t.Fatalf("level with a rollout policy = %d", spec.Level())
	}
	payload, err := Encode(spec)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := Decode(payload); err != nil || *decoded.RolloutPolicy != policy {
		t.Fatalf("Decode = %+v, %v", decoded.RolloutPolicy, err)
	}
	unsafe := policy
	unsafe.CanaryUnits = 0
	invalid := spec
	invalid.RolloutPolicy = &unsafe
	if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("policy without a canary accepted: %v", err)
	}
	base := testSpec(f.id, 1)
	allAtOnce := rollout.DefaultPolicy()
	for name, test := range map[string]struct {
		before, after *rollout.Policy
		change        string
	}{
		"add":    {after: &policy, change: "added"},
		"change": {before: &policy, after: &allAtOnce, change: "updated"},
		"remove": {before: &policy, change: "removed"},
		"keep":   {before: &policy, after: &policy},
	} {
		current, next := base, base
		current.RolloutPolicy, next.RolloutPolicy = test.before, test.after
		next.Generation = 2
		plan, err := Diff(current, next, nil)
		if err != nil || plan.RolloutPolicy != test.change || plan.Empty() != (test.change == "") || len(plan.RootRequired) != 0 {
			t.Errorf("%s: Diff = %+v, %v", name, plan, err)
		}
	}
}

// Desired OCI resources need binary level 7. Only a change that alters the
// cell's OCI resources needs a root: a new or changed enforce entry, prune
// turned on or its delay shortened, and an entry dropped under prune.
func TestOCIDesiredLevelValidateAndWiden(t *testing.T) {
	f := newFixture(t)
	backups := bucket.Spec{Namespace: "tenancy", Bucket: "backups", Versioning: "Enabled"}
	logs := bucket.Spec{Namespace: "tenancy", Bucket: "logs"}
	desired := func(prune bool, delay int, entries map[string]OCIDesiredEntry[bucket.Spec]) *OCIDesired {
		return &OCIDesired{Buckets: entries, Prune: prune, PruneDelaySeconds: delay}
	}
	report := map[string]OCIDesiredEntry[bucket.Spec]{"backups": {Spec: backups}}
	enforced := map[string]OCIDesiredEntry[bucket.Spec]{"backups": {Policy: "enforce", Spec: backups}}
	both := map[string]OCIDesiredEntry[bucket.Spec]{"backups": {Policy: "enforce", Spec: backups}, "logs": {Spec: logs}}

	spec := testSpec(f.id, 1)
	spec.OCIDesired, spec.RequiresBinary = desired(false, 0, enforced), 7
	if spec.Level() != 7 {
		t.Fatalf("level with desired OCI resources = %d", spec.Level())
	}
	payload, err := Encode(spec)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := Decode(payload); err != nil || !reflect.DeepEqual(decoded.OCIDesired, spec.OCIDesired) {
		t.Fatalf("Decode = %+v, %v", decoded.OCIDesired, err)
	}
	for name, invalid := range map[string]*OCIDesired{
		"policy":      desired(false, 0, map[string]OCIDesiredEntry[bucket.Spec]{"b": {Policy: "adopt", Spec: backups}}),
		"spec":        desired(false, 0, map[string]OCIDesiredEntry[bucket.Spec]{"b": {Spec: bucket.Spec{Bucket: "b"}}}),
		"prune delay": desired(true, -1, nil),
	} {
		bad := spec
		bad.OCIDesired = invalid
		if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: invalid desired resources accepted: %v", name, err)
		}
	}

	base := testSpec(f.id, 1)
	for name, test := range map[string]struct {
		before, after *OCIDesired
		change        string
		root          []string
	}{
		"add report":           {after: desired(false, 0, report), change: "added"},
		"add enforce":          {after: desired(false, 0, enforced), change: "added", root: []string{"oci_desired buckets backups"}},
		"report to enforce":    {before: desired(false, 0, report), after: desired(false, 0, enforced), change: "updated", root: []string{"oci_desired buckets backups"}},
		"enforce to report":    {before: desired(false, 0, enforced), after: desired(false, 0, report), change: "updated"},
		"drop without prune":   {before: desired(false, 0, both), after: desired(false, 0, enforced), change: "updated"},
		"drop under prune":     {before: desired(true, 0, both), after: desired(true, 0, enforced), change: "updated", root: []string{"oci_desired buckets logs pruned"}},
		"remove under prune":   {before: desired(true, 0, report), change: "removed"},
		"turn on prune":        {before: desired(false, 0, report), after: desired(true, 0, report), change: "updated", root: []string{"oci_desired prune"}},
		"shorten prune delay":  {before: desired(true, 0, report), after: desired(true, 60, report), change: "updated", root: []string{"oci_desired prune delay"}},
		"lengthen prune delay": {before: desired(true, 60, report), after: desired(true, 0, report), change: "updated"},
		"keep":                 {before: desired(true, 0, both), after: desired(true, 0, both)},
	} {
		current, next := base, base
		current.OCIDesired, next.OCIDesired = test.before, test.after
		next.Generation = 2
		plan, err := Diff(current, next, nil)
		if err != nil || plan.OCIDesired != test.change || plan.Empty() != (test.change == "") ||
			!slices.Equal(plan.RootRequired, test.root) {
			t.Errorf("%s: Diff = %+v, %v", name, plan, err)
		}
	}
}
