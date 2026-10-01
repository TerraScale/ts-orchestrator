package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestVerifiedAnchorWritesToCommandOutput(t *testing.T) {
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	identity, err := protocol.EncodeJSON(bootstrapstart.BakedIdentity{
		SchemaVersion: 1, DeploymentID: fixture.anchor.DeploymentID,
		Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell,
	})
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(fixture.directory, "identity.json")
	writeFixture(t, identityPath, identity, 0o600)
	var output bytes.Buffer
	c := command{ctx: t.Context(), output: &output}
	if err := c.runAt([]string{"verify-anchor", "--anchor", fixture.anchorPath,
		"--identity", identityPath, "--root-key", fixture.rootPath}, fixture.now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"clusterId":"cluster-a"`) {
		t.Fatalf("verification output was not routed to the command writer: %q", output.String())
	}
}
