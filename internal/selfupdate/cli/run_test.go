package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"

	"encoding/base64"

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
	if output, err := invoke(append([]string{"watchdog", "--root", root, "--owner", owner, "--unit", unit}, proof...)...); err != nil ||
		output != "" || len(restarted) != 0 {
		t.Fatalf("idle watchdog = %q %v %v", output, err, restarted)
	}
	if _, err := invoke("bogus"); err == nil {
		t.Fatal("unknown command accepted")
	}
}
