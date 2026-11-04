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
