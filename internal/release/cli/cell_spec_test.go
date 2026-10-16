package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestSignSpecDelegationThenSpec(t *testing.T) {
	fixture := newDelegationFixture(t)
	id := cellspec.Identity{DeploymentID: "0000000000VVK5ZNRRNEED4PH3", Cell: "gru", Environment: "production"}
	candidate, err := cellspec.Encode(cellspec.Spec{Schema: cellspec.Schema, Identity: id, Generation: 3, RequiresBinary: 1,
		Services: []cellspec.Service{{Role: "api", Profile: cellspec.Profile{
			Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}}}}})
	if err != nil {
		t.Fatal(err)
	}
	candidatePath := filepath.Join(fixture.directory, "candidate.json")
	writeFixtureFile(t, candidatePath, candidate, 0o644)
	leafKeyPath := filepath.Join(fixture.directory, "leaf.key")
	writePrivateKey(t, leafKeyPath, fixture.leafPrivate)
	delegationPath := filepath.Join(fixture.directory, "spec.delegation")
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
	err = command{ctx: t.Context(), output: &bytes.Buffer{}}.signSpecDelegationAt(delegationArgs(wrongRoot, rejected), fixture.now)
	if err == nil || !strings.Contains(err.Error(), "does not match root public key") {
		t.Fatalf("wrong root signing key: %v", err)
	}
	if _, err := os.Stat(rejected); !os.IsNotExist(err) {
		t.Fatalf("rejected delegation was written: %v", err)
	}

	var output bytes.Buffer
	c := command{ctx: t.Context(), output: &output}
	if err := c.signSpecDelegationAt(delegationArgs(fixture.privatePath, delegationPath), fixture.now); err != nil {
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
	signedPath := filepath.Join(fixture.directory, "spec.signed")
	setArgs := []string{"--candidate", candidatePath, "--delegation", delegationPath, "--root-key", fixture.rootPath,
		"--signing-key", leafKeyPath, "--out", signedPath}
	if err := c.signSpecAt(setArgs, fixture.now); err != nil {
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
	verified, err := cellspec.VerifyCurrent(wire, roots, id, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Generation != 3 || verified.RootSigned {
		t.Fatalf("verified = %+v", verified)
	}
	sum := sha256.Sum256(wire)
	want := `{"generation":3,"requires_binary":1,"signer":"leaf","sha256":"` + hex.EncodeToString(sum[:]) +
		`","deployment_id":"0000000000VVK5ZNRRNEED4PH3","cell":"gru","environment":"production"}` + "\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
	if err := c.signSpecAt(setArgs, fixture.now); err == nil {
		t.Fatal("sign-spec overwrote its output")
	}

	// The offline root signs a spec itself; the leaf key cannot pose as it,
	// and a signer needs exactly one of --delegation and --root.
	rootSigned := filepath.Join(fixture.directory, "spec.root.signed")
	rootArgs := []string{"--candidate", candidatePath, "--root", "--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath, "--out", rootSigned}
	output.Reset()
	if err := c.signSpecAt(rootArgs, fixture.now); err != nil || !strings.Contains(output.String(), `"signer":"root"`) {
		t.Fatalf("root sign-spec: %v\n%s", err, output.String())
	}
	if verified, err := cellspec.VerifyCurrent(mustReadFile(t, rootSigned), roots, id, fixture.now); err != nil || !verified.RootSigned {
		t.Fatalf("root-signed spec = %+v, %v", verified, err)
	}
	for name, args := range map[string][]string{
		"leaf as root":          {"--candidate", candidatePath, "--root", "--root-key", fixture.rootPath, "--signing-key", leafKeyPath, "--out", filepath.Join(fixture.directory, "a")},
		"root and delegation":   append(slices.Clone(rootArgs[:len(rootArgs)-1]), filepath.Join(fixture.directory, "b"), "--delegation", delegationPath),
		"neither root nor leaf": {"--candidate", candidatePath, "--root-key", fixture.rootPath, "--signing-key", leafKeyPath, "--out", filepath.Join(fixture.directory, "c")},
	} {
		if err := c.signSpecAt(args, fixture.now); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
