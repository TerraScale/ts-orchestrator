package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func TestIdentityRekeyCandidateRequiresExactSignedELFAndDecoder(t *testing.T) {
	data, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	accepted := controllerAcceptedFixture(t, data)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	useAcceptedController(t, accepted, roots)
	inputs, err := acceptedTrustInputs(accepted)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	receipt, delegation := signAcceptedSuccessor(t, data, now, private, roots)
	candidate := filepath.Join(t.TempDir(), "candidate")
	if err := os.WriteFile(candidate, data, 0o755); err != nil {
		t.Fatal(err)
	}
	checks := 0
	checkAcceptedBinary = func(context.Context, string, bootstrapstart.AcceptedIdentity) error { checks++; return nil }
	verify := func(record bootstrapstart.AcceptedIdentity, trustInputs bootstrapstart.TrustInputs, path string, at time.Time) error {
		return verifyIdentityRekeyCandidate(t.Context(), record, trustInputs, path, receipt, delegation, at, uint32(os.Getuid()), true)
	}
	if err := verify(accepted, inputs, candidate, now); err != nil || checks != 1 {
		t.Fatalf("candidate preflight: checks=%d error=%v", checks, err)
	}
	wrong := accepted.Clone()
	wrong.Binary.Size++
	wrong.ControllerBindings[0].Binary = wrong.Binary
	if err := verify(wrong, inputs, candidate, now); err == nil {
		t.Fatal("wrong checkpoint binary size accepted")
	}
	if err := verify(accepted, inputs, candidate, now.Add(time.Hour)); err == nil {
		t.Fatal("expired release authorization accepted")
	}
	symlink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(candidate, symlink); err != nil {
		t.Fatal(err)
	}
	if err := verify(accepted, inputs, symlink, now); err == nil {
		t.Fatal("symlink candidate accepted")
	}
	checkAcceptedBinary = func(context.Context, string, bootstrapstart.AcceptedIdentity) error {
		return errors.New("incompatible accepted decoder")
	}
	if err := verify(accepted, inputs, candidate, now); err == nil {
		t.Fatal("incompatible decoder accepted")
	}
	checkAcceptedBinary = func(context.Context, string, bootstrapstart.AcceptedIdentity) error {
		t.Fatal("altered binary executed")
		return nil
	}
	data[0] ^= 1
	if err := os.WriteFile(candidate, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verify(accepted, inputs, candidate, now); err == nil {
		t.Fatal("altered artifact accepted")
	}
}

func TestIdentityRekeyBinaryInstallRequiresStoppedController(t *testing.T) {
	if err := controllerStoppedState([]byte("ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\n")); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"", "ActiveState=active\nSubState=running\nMainPID=42\nControlPID=0", "ActiveState=inactive\nSubState=dead\nMainPID=42\nControlPID=0", "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=42", "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nActiveState=inactive"} {
		if err := controllerStoppedState([]byte(state)); err == nil {
			t.Fatalf("serving or ambiguous service state accepted: %q", state)
		}
	}
}
