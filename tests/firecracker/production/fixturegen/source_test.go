package fixturegen

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func sourceFixture(t *testing.T) (string, []SourcePin) {
	t.Helper()
	root := t.TempDir()
	var pins []SourcePin
	for _, path := range RequiredSourcePaths() {
		name := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		body := []byte(path)
		if err := os.WriteFile(name, body, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		pins = append(pins, SourcePin{Path: path, SHA256: hex.EncodeToString(digest[:])})
	}
	return root, pins
}

func TestVerifySourcePinsRejectsChangedMissingOrEscapedSource(t *testing.T) {
	root, pins := sourceFixture(t)
	if err := VerifySourcePins(root, pins); err != nil {
		t.Fatal(err)
	}
	changed := filepath.Join(root, "internal", "bootstrap", "ledger.go")
	if err := os.WriteFile(changed, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourcePins(root, pins); err == nil {
		t.Fatal("changed source passed pin")
	}
	if err := os.WriteFile(changed, []byte("internal/bootstrap/ledger.go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourcePins(root, pins); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourcePins(root, pins[:1]); err == nil {
		t.Fatal("incomplete mandatory source baseline accepted")
	}
	bad := append([]SourcePin{{Path: "../outside", SHA256: pins[0].SHA256}}, pins...)
	if err := VerifySourcePins(root, bad); err == nil {
		t.Fatal("source traversal accepted")
	} else if err.Error() != `invalid source pin "../outside"` {
		t.Fatalf("source traversal error = %v, want invalid escaped pin", err)
	}
	bad = slices.Clone(pins)
	bad[0].SHA256 = strings.Repeat("X", 64)
	if err := VerifySourcePins(root, bad); err == nil {
		t.Fatal("invalid source digest accepted")
	}
	// Keep bytes and pins equal, but replace an ancestor with a symlink.
	outside := t.TempDir()
	if err := os.Rename(filepath.Join(root, "internal", "app"), filepath.Join(outside, "app")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "app"), filepath.Join(root, "internal", "app")); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourcePins(root, pins); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
}
