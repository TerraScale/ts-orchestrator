package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// The old root and the new root sign in turn; the statement is complete
// only with both, and a stranger's key or a mismatched statement is refused.
func TestSignRootRotationCollectsOldAndNewRootSignatures(t *testing.T) {
	fixture := newDelegationFixture(t)
	dir := fixture.directory
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub, newKey := filepath.Join(dir, "new.pub"), filepath.Join(dir, "new.key")
	writePublicKey(t, newPub, newPublic)
	writePrivateKey(t, newKey, newPrivate)
	strangerKey := filepath.Join(dir, "stranger.key")
	writePrivateKey(t, strangerKey, fixture.leafPrivate)
	chainPath := filepath.Join(dir, "chain.json")
	writeFixtureFile(t, chainPath, []byte(`{"version":1,"rotations":[]}`), 0o644)
	id := trust.ChainIdentity{DeploymentID: "0000000000VVK5ZNRRNEED4PH3", Cell: "gru", Environment: "production"}
	sign := func(key, signed, out string, newRoots ...string) (string, error) {
		args := []string{"--genesis-root", fixture.rootPath, "--chain", chainPath, "--deployment-id", id.DeploymentID,
			"--cell", id.Cell, "--environment", id.Environment, "--signing-key", key, "--out", out}
		for _, root := range newRoots {
			args = append(args, "--new-root", root)
		}
		if signed != "" {
			args = append(args, "--signed", signed)
		}
		var output bytes.Buffer
		err := command{ctx: t.Context(), output: &output}.signRootRotationAt(args, fixture.now)
		return output.String(), err
	}

	if _, err := sign(strangerKey, "", filepath.Join(dir, "stranger.json"), newPub); err == nil ||
		!strings.Contains(err.Error(), "neither a current nor a new root") {
		t.Fatalf("stranger key: %v", err)
	}
	partial := filepath.Join(dir, "partial.json")
	if out, err := sign(fixture.privatePath, "", partial, newPub); err != nil || !strings.Contains(out, `"complete":false`) {
		t.Fatalf("old root: %v\n%s", err, out)
	}
	if _, err := sign(newKey, partial, filepath.Join(dir, "other.json"), fixture.leafPath); err == nil ||
		!strings.Contains(err.Error(), "different statement") {
		t.Fatalf("mismatched statement: %v", err)
	}
	if _, err := sign(fixture.privatePath, partial, filepath.Join(dir, "twice.json"), newPub); err == nil {
		t.Fatal("the old root signed twice")
	}
	// A partly signed rotation whose signature expired cannot be completed.
	later := command{ctx: t.Context(), output: &bytes.Buffer{}}
	expiredArgs := []string{"--genesis-root", fixture.rootPath, "--chain", chainPath, "--deployment-id", id.DeploymentID,
		"--cell", id.Cell, "--environment", id.Environment, "--signing-key", newKey, "--new-root", newPub,
		"--signed", partial, "--out", filepath.Join(dir, "expired.json")}
	if err := later.signRootRotationAt(expiredArgs, fixture.now.Add(25*time.Hour)); err == nil ||
		!strings.Contains(err.Error(), "no longer current") {
		t.Fatalf("expired partial rotation: %v", err)
	}
	complete := filepath.Join(dir, "complete.json")
	if out, err := sign(newKey, partial, complete, newPub); err != nil || !strings.Contains(out, `"complete":true`) {
		t.Fatalf("new root: %v\n%s", err, out)
	}

	wire, err := os.ReadFile(complete)
	if err != nil {
		t.Fatal(err)
	}
	var signed trust.SignedRotation
	if err := protocol.DecodeStrict(wire, &signed, trust.MaxRootChainBytes); err != nil {
		t.Fatal(err)
	}
	genesis, err := trust.ParseKeyring(fixture.rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := trust.VerifyRootChain(genesis, id, trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{signed}})
	newID, _ := trust.KeyID(newPublic)
	if err != nil || verified.Sequence != 1 || len(verified.Current) != 1 || verified.Current[newID] == nil {
		t.Fatalf("signed rotation verifies to %+v, %v", verified, err)
	}
}
