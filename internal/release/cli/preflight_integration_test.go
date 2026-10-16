package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/release"
)

func TestProductionDeployRefusesBeforeSigningCredentials(t *testing.T) {
	fixture := newApplyHTTPFixture(t)
	for _, cell := range []string{"FRA", "GRU", "SFO"} {
		if err := os.Remove(filepath.Join(fixture.releaseDir, "production", cell, "amd64", "production.json")); err != nil {
			t.Fatal(err)
		}
	}
	// This source proof is fixture-local; candidate files, signatures and storage
	// use the real boundaries. No production credentials are available to the test.
	fixture.env.check = func(q release.Qualification, digest string) error { return q.MatchBinary(fixture.binary, digest) }
	fixture.env.secret = readVaultSecret
	args := []string{"--dir", fixture.releaseDir, "--source-revision", fixture.binary.SourceRevision,
		"--update-delegation-secret", "unavailable", "--signing-key-secret", "unavailable", "--vault-id", "invalid-vault",
		"--root-key", fixture.rootPath, "--environment", "production", "--source-checkout", fixture.sourceDir,
		"--namespace", "ns", "--arch", "amd64", "--cell", "GRU", "--cell", "SFO", "--cell", "FRA"}
	err := (command{ctx: t.Context(), output: io.Discard}).deployWith(args, fixture.env)
	if !errors.Is(err, release.ErrProductionQualification) {
		t.Fatalf("unqualified candidate reached signing credential lookup: %v", err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.channelWrites) != 0 || len(fixture.binaryCreates) != 0 {
		t.Fatal("unqualified candidate mutated storage")
	}
}
