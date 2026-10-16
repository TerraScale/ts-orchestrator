package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestFunctionAdmissionFilesystemBundle(t *testing.T) {
	fixture := newFunctionFixture(t)
	signed, err := SignFunctionClaim(fixture.claim, fixture.module, fixture.delegation,
		fixture.roots, fixture.leaf, fixture.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, content := range map[string][]byte{
		"module.wasm":     fixture.module,
		"receipt.json":    encodeEnvelope(t, signed),
		"delegation.json": encodeEnvelope(t, fixture.delegation),
		"root.pub":        fixture.root,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(name string) []byte {
		t.Helper()
		wire, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	roots, err := trust.ParseKeyring(ed25519.PublicKey(read("root.pub")))
	if err != nil {
		t.Fatal(err)
	}
	module := read("module.wasm")
	verified, err := VerifyFunctionCurrent(read("receipt.json"), read("delegation.json"), module,
		roots, fixture.expected(), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Valid() || !bytes.Equal(verified.Module(), fixture.module) || verified.Claim().Digest != fixture.claim.Digest ||
		verified.EnvelopeSHA256() != fingerprintWire(t, read("receipt.json")) {
		t.Fatalf("proof does not retain the admitted module and envelope: %+v", verified)
	}
	module[0] ^= 1
	if err := os.WriteFile(filepath.Join(dir, "module.wasm"), module, 0o600); err != nil {
		t.Fatal(err)
	}
	returned := verified.Module()
	returned[1] ^= 1
	if !bytes.Equal(verified.Module(), fixture.module) {
		t.Fatal("caller or artifact mutation changed admitted bytes")
	}
	if _, err := VerifyFunctionCurrent(read("receipt.json"), read("delegation.json"), read("module.wasm"),
		roots, fixture.expected(), fixture.now); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("tampered on-disk module error = %v", err)
	}
	if (VerifiedFunction{}).Valid() {
		t.Fatal("zero proof grants execution authority")
	}
}

func TestFunctionAdmissionRejectsScopeOrderAndTrust(t *testing.T) {
	fixture := newFunctionFixture(t)
	signed, err := SignFunctionClaim(fixture.claim, fixture.module, fixture.delegation,
		fixture.roots, fixture.leaf, fixture.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, grant := encodeEnvelope(t, signed), encodeEnvelope(t, fixture.delegation)
	for _, test := range []struct {
		name   string
		change func(*FunctionExpectation)
	}{
		{"tenant", func(e *FunctionExpectation) { e.TenantID = entityid.Derive("tenant", "other") }},
		{"function", func(e *FunctionExpectation) { e.FunctionID = "other" }},
		{"revision", func(e *FunctionExpectation) { e.Revision = "other" }},
		{"digest", func(e *FunctionExpectation) { e.Digest = hex.EncodeToString(make([]byte, sha256.Size)) }},
		{"environment", func(e *FunctionExpectation) { e.Environment = "production" }},
		{"cell", func(e *FunctionExpectation) { e.Cell = "FRA" }},
		{"stale-sequence", func(e *FunctionExpectation) { e.MinimumSequence++ }},
		{"missing-floor", func(e *FunctionExpectation) { e.MinimumSequence = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			expected := fixture.expected()
			test.change(&expected)
			if _, err := VerifyFunctionCurrent(wire, grant, fixture.module, fixture.roots, expected, fixture.now); !errors.Is(err, ErrExpectationMismatch) {
				t.Fatalf("scope mismatch error = %v", err)
			}
		})
	}
	if _, err := VerifyFunctionCurrent(wire, grant, fixture.module, trust.Keyring{}, fixture.expected(), fixture.now); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("unknown root error = %v", err)
	}
	if _, err := VerifyFunctionCurrent(wire, grant, fixture.module, fixture.roots, fixture.expected(), signed.ExpiresAt); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired receipt error = %v", err)
	}
	signed.Scope.Cell = "FRA"
	if _, err := VerifyFunctionCurrent(encodeEnvelope(t, signed), grant, fixture.module, fixture.roots, fixture.expected(), fixture.now); !errors.Is(err, trust.ErrScopeMismatch) {
		t.Fatalf("modified signed scope error = %v", err)
	}
}

func TestFunctionAdmissionRequiresExactDelegationAndSupportedContract(t *testing.T) {
	fixture := newFunctionFixture(t)
	for _, test := range []struct {
		name   string
		change func(*FunctionClaim)
	}{
		{"abi", func(c *FunctionClaim) { c.ABI = "terrascale.function.component.v1" }},
		{"capability", func(c *FunctionClaim) { c.Capabilities = []string{"network"} }},
		{"canonical-tenant", func(c *FunctionClaim) { c.TenantID = "tenant-name" }},
		{"revision", func(c *FunctionClaim) { c.Revision = "../other" }},
		{"size", func(c *FunctionClaim) { c.Bytes++ }},
		{"oversize", func(c *FunctionClaim) { c.Bytes = MaxFunctionModuleBytes + 1 }},
		{"sequence", func(c *FunctionClaim) { c.Sequence = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim := fixture.claim
			test.change(&claim)
			if _, err := SignFunctionClaim(claim, fixture.module, fixture.delegation, fixture.roots, fixture.leaf, fixture.now, time.Hour); !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("unsupported claim signer error = %v", err)
			}
			// Even a valid leaf signature cannot admit an unsupported contract.
			signed := signDirect(t, claim, FunctionScope(fixture.claim), fixture.leaf, fixture.now, fixture.now.Add(time.Hour))
			if _, err := VerifyFunctionCurrent(encodeEnvelope(t, signed), encodeEnvelope(t, fixture.delegation), fixture.module,
				fixture.roots, fixture.expected(), fixture.now); !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("unsupported signed claim verifier error = %v", err)
			}
		})
	}
	other := fixture.claim
	other.FunctionID = "unauthorized"
	if _, err := SignFunctionClaim(other, fixture.module, fixture.delegation, fixture.roots, fixture.leaf, fixture.now, time.Hour); !errors.Is(err, trust.ErrCapabilityDenied) {
		t.Fatalf("cross-function delegated signer error = %v", err)
	}
	otherSigned := signDirect(t, other, FunctionScope(other), fixture.leaf, fixture.now, fixture.now.Add(time.Hour))
	expected := fixture.expected()
	expected.FunctionID = other.FunctionID
	if _, err := VerifyFunctionCurrent(encodeEnvelope(t, otherSigned), encodeEnvelope(t, fixture.delegation), fixture.module,
		fixture.roots, expected, fixture.now); !errors.Is(err, trust.ErrCapabilityDenied) {
		t.Fatalf("cross-function delegated verifier error = %v", err)
	}
	// Signed payload changes must fail even when the expected identity agrees.
	original := signDirect(t, fixture.claim, FunctionScope(fixture.claim), fixture.leaf, fixture.now, fixture.now.Add(time.Hour))
	changed := fixture.claim
	changed.Sequence++
	payload, err := trust.EncodePayload(changed)
	if err != nil {
		t.Fatal(err)
	}
	original.Payload = payload
	if _, err := VerifyFunctionCurrent(encodeEnvelope(t, original), encodeEnvelope(t, fixture.delegation), fixture.module,
		fixture.roots, fixture.expected(), fixture.now); !errors.Is(err, trust.ErrBadSignature) {
		t.Fatalf("tampered signed sequence error = %v", err)
	}
}

type functionFixture struct {
	claim       FunctionClaim
	module      []byte
	root        ed25519.PublicKey
	rootPrivate ed25519.PrivateKey
	leaf        ed25519.PrivateKey
	roots       trust.Keyring
	delegation  trust.Envelope
	now         time.Time
}

func newFunctionFixture(t *testing.T) functionFixture {
	t.Helper()
	module, err := hex.DecodeString("0061736d0100000001040160000003020100070a01065f737461727400000a040102000b")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(module)
	claim := FunctionClaim{
		Schema: FunctionSchema, ABI: FunctionABI, TenantID: entityid.Derive("tenant", "function-test"),
		FunctionID: "echo", Revision: "first", Digest: hex.EncodeToString(digest[:]), Bytes: int64(len(module)),
		Capabilities: []string{}, Environment: "canary", Cell: "GRU", Sequence: 42,
	}
	root, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leaf, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := FunctionScope(claim)
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encodedPublic,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}},
	}, now.Add(-time.Minute), now.Add(2*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	return functionFixture{claim: claim, module: module, root: root, rootPrivate: rootPrivate, leaf: leaf, roots: roots, delegation: delegation, now: now}
}

func (fixture functionFixture) expected() FunctionExpectation {
	claim := fixture.claim
	return FunctionExpectation{Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID,
		FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: claim.Sequence}
}

func TestFunctionAdmissionCannotOutliveDelegatedSigningAuthority(t *testing.T) {
	fixture := newFunctionFixture(t)
	var capability trust.Delegation
	if err := json.Unmarshal(fixture.delegation.Payload, &capability); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Truncate(time.Second).Add(3 * time.Second)
	delegation, err := trust.SignDelegation(capability, fixture.now.Add(-time.Minute), expires, fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	// A delegated signer can bypass the producer's lifetime clamp.
	signed := signDirect(t, fixture.claim, FunctionScope(fixture.claim), fixture.leaf, fixture.now, fixture.now.Add(time.Hour))
	if _, err := VerifyFunctionCurrent(encodeEnvelope(t, signed), encodeEnvelope(t, delegation), fixture.module, fixture.roots, fixture.expected(), time.Now()); !errors.Is(err, trust.ErrDelegationTime) {
		t.Fatalf("receipt outliving its delegation was admitted: %v", err)
	}
	signed = signDirect(t, fixture.claim, FunctionScope(fixture.claim), fixture.leaf, fixture.now, expires)
	proof, err := VerifyFunctionCurrent(encodeEnvelope(t, signed), encodeEnvelope(t, delegation), fixture.module, fixture.roots, fixture.expected(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Valid() || !proof.ExpiresAt().Equal(expires) {
		t.Fatalf("proof exceeds delegation expiry: %v", proof.ExpiresAt())
	}
	time.Sleep(time.Until(expires) + 10*time.Millisecond)
	if proof.Valid() {
		t.Fatal("retained proof remains authorized after delegation expires")
	}
}
