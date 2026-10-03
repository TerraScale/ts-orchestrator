package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrepareActivateWatchdogRestart(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	owner := fmt.Sprint(os.Getuid())
	baked := filepath.Join(dir, "baked")
	if err := os.WriteFile(baked, []byte("baked build"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "identity.key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(private)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	var restarted []string
	invoke := func(args ...string) (string, error) {
		var output bytes.Buffer
		err := run(t.Context(), args, &output, func() time.Time { return now }, func(_ context.Context, unit string) error {
			restarted = append(restarted, unit)
			return nil
		})
		return output.String(), err
	}
	unit := "terrascale-orchestrator-host.service"
	proof := []string{"--proof-file", filepath.Join(dir, "proof.json"), "--proof-key-file", keyFile}
	output, err := invoke(append([]string{"prepare", "--root", root, "--owner", owner, "--unit", unit, "--baked-binary", baked}, proof...)...)
	if err != nil || !strings.Contains(output, "outcome=idle") {
		t.Fatalf("prepare = %q %v", output, err)
	}
	if output, err := invoke("status", "--root", root, "--owner", owner); err != nil || !strings.Contains(output, "pending=none") {
		t.Fatalf("status = %q %v", output, err)
	}
	// Without a staged second release nothing can be activated.
	if _, err := invoke("activate", "--root", root, "--owner", owner, "--release", strings.Repeat("a", 64), "--unit", unit); err == nil {
		t.Fatal("unstaged release activated")
	}
	if _, err := invoke("stage", "--root", root); err == nil {
		t.Fatal("stage without a receipt accepted")
	}
	if _, err := invoke("watchdog", "--root", root, "--owner", owner, "--unit", unit, "--proof-file", "x"); err == nil {
		t.Fatal("half-configured proof accepted")
	}
	if output, err := invoke(append([]string{"watchdog", "--root", root, "--owner", owner, "--unit", unit, "--restart"}, proof...)...); err != nil ||
		!strings.Contains(output, "outcome=idle") || len(restarted) != 0 {
		t.Fatalf("idle watchdog = %q %v %v", output, err, restarted)
	}
	if _, err := invoke("bogus"); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func TestReadKeys(t *testing.T) {
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(dir, "root.pub")
	if err := os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0o644); err != nil {
		t.Fatal(err)
	}
	if roots, err := readRootKeyring(rootFile); err != nil || len(roots) != 1 {
		t.Fatalf("root keyring = %v %v", roots, err)
	}
	keyFile := filepath.Join(dir, "identity.key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(private)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentityPublicKey(keyFile); err == nil {
		t.Fatal("world-readable identity key accepted")
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if derived, err := readIdentityPublicKey(keyFile); err != nil || !derived.Equal(public) {
		t.Fatalf("derived public key = %v", err)
	}
}
