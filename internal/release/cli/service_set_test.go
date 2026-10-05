package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/serviceset"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func TestSignServiceDelegationThenServiceSet(t *testing.T) {
	fixture := newDelegationFixture(t)
	id := serviceset.Identity{DeploymentID: "terrascale-prod", Cell: "gru", Environment: "production"}
	candidate, err := serviceset.Encode(serviceset.Set{Schema: serviceset.Schema, Identity: id, Generation: 3,
		Services: []serviceset.Service{{Role: "api", Profile: serviceset.Profile{
			Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}}}}})
	if err != nil {
		t.Fatal(err)
	}
	candidatePath := filepath.Join(fixture.directory, "candidate.json")
	writeFixtureFile(t, candidatePath, candidate, 0o644)
	leafKeyPath := filepath.Join(fixture.directory, "leaf.key")
	writePrivateKey(t, leafKeyPath, fixture.leafPrivate)
	delegationPath := filepath.Join(fixture.directory, "service.delegation")
	delegationArgs := func(signingKey, output string) []string {
		return []string{"--subject-public-key", fixture.leafPath, "--root-key", fixture.rootPath,
			"--signing-key", signingKey, "--deployment-id", id.DeploymentID, "--cell", id.Cell,
			"--environment", id.Environment,
			"--issued-at", fixture.now.Add(-time.Minute).Format(time.RFC3339),
			"--expires-at", fixture.now.Add(24 * time.Hour).Format(time.RFC3339), "--out", output}
	}

	wrongRoot := filepath.Join(fixture.directory, "wrong-root.key")
	writePrivateKey(t, wrongRoot, fixture.leafPrivate)
	rejected := filepath.Join(fixture.directory, "rejected.delegation")
	err = command{ctx: t.Context(), output: &bytes.Buffer{}}.signServiceDelegationAt(delegationArgs(wrongRoot, rejected), fixture.now)
	if err == nil || !strings.Contains(err.Error(), "does not match root public key") {
		t.Fatalf("wrong root signing key: %v", err)
	}
	if _, err := os.Stat(rejected); !os.IsNotExist(err) {
		t.Fatalf("rejected delegation was written: %v", err)
	}

	var output bytes.Buffer
	c := command{ctx: t.Context(), output: &output}
	if err := c.signServiceDelegationAt(delegationArgs(fixture.privatePath, delegationPath), fixture.now); err != nil {
		t.Fatal(err)
	}
	delegationWire, err := os.ReadFile(delegationPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.DecodeEnvelope(delegationWire); err != nil {
		t.Fatal(err)
	}
	var delegationResult struct {
		Delegation string `json:"delegation"`
		SHA256     string `json:"sha256"`
	}
	if err := json.Unmarshal(output.Bytes(), &delegationResult); err != nil {
		t.Fatalf("delegation output %q: %v", output.String(), err)
	}
	if sum := sha256.Sum256(delegationWire); delegationResult.Delegation != delegationPath ||
		delegationResult.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("delegation output = %+v", delegationResult)
	}

	output.Reset()
	signedPath := filepath.Join(fixture.directory, "service-set.signed")
	setArgs := []string{"--candidate", candidatePath, "--delegation", delegationPath, "--root-key", fixture.rootPath,
		"--signing-key", leafKeyPath, "--out", signedPath}
	if err := c.signServiceSetAt(setArgs, fixture.now); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(fixture.rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	set, err := serviceset.VerifyCurrent(wire, roots, id, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if set.Generation != 3 {
		t.Fatalf("generation = %d", set.Generation)
	}
	sum := sha256.Sum256(wire)
	want := `{"generation":3,"sha256":"` + hex.EncodeToString(sum[:]) +
		`","deployment_id":"terrascale-prod","cell":"gru","environment":"production"}` + "\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
	if err := c.signServiceSetAt(setArgs, fixture.now); err == nil {
		t.Fatal("sign-service-set overwrote its output")
	}
}
