package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

func TestSelfUpdateProofUsesTheConfiguredReleaseRoot(t *testing.T) {
	if got := selfUpdateRoot(""); got != selfupdate.DefaultRoot {
		t.Fatalf("default root = %q, want %q", got, selfupdate.DefaultRoot)
	}
	custom := filepath.Join(t.TempDir(), "releases-root")
	if got := selfUpdateRoot(custom); got != custom {
		t.Fatalf("configured root = %q, want %q", got, custom)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A configured root without a pending activation emits nothing and
	// never falls back to the default root.
	var output bytes.Buffer
	emitSelfUpdateProofWithKey(filepath.Join(t.TempDir(), "proof.json"), custom, key, controllerUnit, &output)
	if output.Len() != 0 {
		t.Fatalf("proof emitted without a pending activation: %q", output.String())
	}
	if _, err := selfupdate.EmitProof(selfupdate.NewLayout("relative/root"), controllerUnit, "/proof.json", key, time.Now()); err == nil {
		t.Fatal("a relative release root was accepted")
	}
}

// An unset proof file defaults to the file the image's watchdog reads for the
// unit, beside the configured release root (TS-553).
func TestSelfUpdateProofFileDefaultsToTheWatchdogFile(t *testing.T) {
	for unit, want := range map[string]string{
		controllerUnit: "/var/lib/terrascale-orchestrator-controller/selfupdate-proof.json",
		hostUnit:       "/var/lib/terrascale-orchestrator-host/selfupdate-proof.json",
	} {
		if got := selfUpdateProofFile("", "", unit); got != want {
			t.Fatalf("%s default proof = %q, want %q", unit, got, want)
		}
	}
	if got := selfUpdateProofFile("", "/srv/lab/releases", hostUnit); got != "/srv/lab/terrascale-orchestrator-host/selfupdate-proof.json" {
		t.Fatalf("default proof beside a configured root = %q", got)
	}
	if got := selfUpdateProofFile("/run/proof.json", "", hostUnit); got != "/run/proof.json" {
		t.Fatalf("configured proof = %q", got)
	}
}
