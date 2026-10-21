package bootstrapstart

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestVerifyRestartProcessBinaryUsesCurrentSignedRelease(t *testing.T) {
	if os.Geteuid() != 0 || runtime.GOARCH != "amd64" {
		t.Skip("requires root and the amd64 signed-update fixture")
	}
	running, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	accepted := acceptedIdentityFixture(t)
	accepted.Environment = "production"
	accepted.Binary = identityrekey.BinaryPin{SHA256: digest(running), Size: int64(len(running)), Architecture: runtime.GOARCH}
	if err := VerifyRestartProcessBinary(os.Getpid(), accepted, selfupdate.Layout{}, nil); err != nil {
		t.Fatalf("accepted executable baseline: %v", err)
	}
	if err := VerifyRestartProcessBinary(0, accepted, selfupdate.Layout{}, nil); err == nil {
		t.Fatal("invalid process ID admitted")
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	baked := filepath.Join(t.TempDir(), "baked")
	baseline := elfFixture("accepted image baseline")
	if err := os.WriteFile(baked, baseline, 0o555); err != nil {
		t.Fatal(err)
	}
	accepted.Binary = identityrekey.BinaryPin{SHA256: digest(baseline), Size: int64(len(baseline)), Architecture: runtime.GOARCH}
	if err := VerifyRestartProcessBinary(os.Getpid(), accepted, selfupdate.Layout{}, roots); err == nil {
		t.Fatal("unaccepted executable admitted without a signed current release")
	}
	f := newSelfUpdateFixture(t, roots, private, baked, time.Now().UTC().Truncate(time.Second).Add(-2*time.Hour))
	receipt, delegation := f.updateReceipt(running, accepted.Environment, accepted.Cell)
	previous := f.activate(running, receipt, delegation)
	if err := VerifyRestartProcessBinary(os.Getpid(), accepted, f.layout, roots); err != nil {
		t.Fatalf("current update with historically verified receipt: %v", err)
	}
	wrongScope := accepted.Clone()
	wrongScope.Environment = "canary"
	if err := VerifyRestartProcessBinary(os.Getpid(), wrongScope, f.layout, roots); err == nil {
		t.Fatal("current update admitted for another environment")
	}
	if err := os.WriteFile(filepath.Join(f.layout.Root, "known-bad.json"), []byte(`{"digests":["`+previous+`"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRestartProcessBinary(os.Getpid(), accepted, f.layout, roots); err == nil {
		t.Fatal("known-bad current update admitted")
	}
	if err := os.Remove(filepath.Join(f.layout.Root, "known-bad.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/"+previous, filepath.Join(f.layout.Root, "known-good")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.layout.Root, "activation.json")); err != nil {
		t.Fatal(err)
	}
	target := elfFixture("next signed update")
	receipt, delegation = f.updateReceipt(target, accepted.Environment, accepted.Cell)
	f.activate(target, receipt, delegation)
	if _, err := verifyRecoveryPredecessor("/proc/self/exe", f.layout, roots, accepted); err != nil {
		t.Fatalf("fixture is not a signed recovery predecessor: %v", err)
	}
	if err := VerifyRestartProcessBinary(os.Getpid(), accepted, f.layout, roots); err == nil {
		t.Fatal("recovery-only predecessor admitted as a controller process")
	}
}
