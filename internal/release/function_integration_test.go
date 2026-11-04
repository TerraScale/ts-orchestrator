package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

type functionFixture struct {
	claim      FunctionClaim
	module     []byte
	root       ed25519.PublicKey
	leaf       ed25519.PrivateKey
	roots      trust.Keyring
	delegation trust.Envelope
	now        time.Time
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
	return functionFixture{claim: claim, module: module, root: root, leaf: leaf, roots: roots, delegation: delegation, now: now}
}

func (fixture functionFixture) expected() FunctionExpectation {
	claim := fixture.claim
	return FunctionExpectation{Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID,
		FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: claim.Sequence}
}
