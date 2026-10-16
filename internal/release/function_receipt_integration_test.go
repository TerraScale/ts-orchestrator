package release

import (
	"bytes"
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

func TestFunctionReceiptFilesystemVerificationKeepsExecutionSeparate(t *testing.T) {
	fixture := newFunctionFixture(t)
	fixture.module = bytes.Repeat([]byte{0x42}, MaxFunctionModuleBytes)
	digest := sha256.Sum256(fixture.module)
	fixture.claim.Digest, fixture.claim.Bytes = hex.EncodeToString(digest[:]), int64(len(fixture.module))
	signed, err := SignFunctionClaim(fixture.claim, fixture.module, fixture.delegation, fixture.roots, fixture.leaf, fixture.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	wire, grant := encodeEnvelope(t, signed), encodeEnvelope(t, fixture.delegation)
	if len(wire)+len(grant) > 128<<10 {
		t.Fatal("metadata exceeds the registry snapshot bound")
	}
	for name, content := range map[string][]byte{"receipt.json": wire, "delegation.json": grant} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		readback, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if name == "receipt.json" {
			wire = readback
		} else {
			grant = readback
		}
	}
	receipt, err := VerifyFunctionReceiptCurrent(wire, grant, fixture.roots, fixture.expected(), fixture.now)
	if err != nil || !receipt.Valid() || receipt.Claim().Digest != fixture.claim.Digest ||
		receipt.Claim().Bytes != MaxFunctionModuleBytes || receipt.EnvelopeSHA256() != fingerprintWire(t, wire) || !receipt.ExpiresAt().Equal(signed.ExpiresAt) {
		t.Fatalf("current metadata receipt: %+v, %v", receipt, err)
	}
	if _, ok := any(receipt).(interface{ Module() []byte }); ok {
		t.Fatal("metadata receipt exposes module execution material")
	}
	if _, ok := any(receipt).(VerifiedFunction); ok || (VerifiedFunctionReceipt{}).Valid() {
		t.Fatal("metadata receipt grants execution or its zero value grants trust")
	}
	for _, module := range [][]byte{nil, []byte("wrong module")} {
		if _, err := VerifyFunctionCurrent(wire, grant, module, fixture.roots, fixture.expected(), fixture.now); !errors.Is(err, ErrInvalidReceipt) {
			t.Fatalf("module execution verifier accepted missing or mismatched bytes: %v", err)
		}
	}
}

func TestFunctionReceiptRejectsScopeOrderAndTrust(t *testing.T) {
	fixture := newFunctionFixture(t)
	signed, err := SignFunctionClaim(fixture.claim, fixture.module, fixture.delegation, fixture.roots, fixture.leaf, fixture.now, time.Hour)
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
		{"sequence", func(e *FunctionExpectation) { e.MinimumSequence++ }},
		{"missing floor", func(e *FunctionExpectation) { e.MinimumSequence = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			expected := fixture.expected()
			test.change(&expected)
			if _, err := VerifyFunctionReceiptCurrent(wire, grant, fixture.roots, expected, fixture.now); !errors.Is(err, ErrExpectationMismatch) {
				t.Fatalf("unexpected scope/order error: %v", err)
			}
		})
	}
	if _, err := VerifyFunctionReceiptCurrent(wire, grant, trust.Keyring{}, fixture.expected(), fixture.now); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("unknown root: %v", err)
	}
	if _, err := VerifyFunctionReceiptCurrent(wire, grant, fixture.roots, fixture.expected(), signed.ExpiresAt); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired receipt: %v", err)
	}
	other := fixture.claim
	other.FunctionID = "unauthorized"
	unauthorized := signDirect(t, other, FunctionScope(other), fixture.leaf, fixture.now, fixture.now.Add(time.Hour))
	expected := fixture.expected()
	expected.FunctionID = other.FunctionID
	if _, err := VerifyFunctionReceiptCurrent(encodeEnvelope(t, unauthorized), grant, fixture.roots, expected, fixture.now); !errors.Is(err, trust.ErrCapabilityDenied) {
		t.Fatalf("cross-function delegation: %v", err)
	}
	signed.Scope.Cell = "FRA"
	if _, err := VerifyFunctionReceiptCurrent(encodeEnvelope(t, signed), grant, fixture.roots, fixture.expected(), fixture.now); !errors.Is(err, trust.ErrScopeMismatch) {
		t.Fatalf("tampered signed scope: %v", err)
	}
}
