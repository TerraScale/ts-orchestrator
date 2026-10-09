package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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
	if !strings.Contains(output.String(), `"clusterId":"0000000000RMSAJ9B0JFV7ESHN"`) {
		t.Fatalf("verification output was not routed to the command writer: %q", output.String())
	}
}

type failedBootstrapOutput struct {
	err error
}

func (output failedBootstrapOutput) Write(contents []byte) (int, error) {
	return 0, output.err
}

func ledgerSigningCommand(t *testing.T) (*manifestFixture, []string, string, time.Time) {
	t.Helper()
	fixture := newManifestFixture(t, 30*24*time.Hour, 20*24*time.Hour)
	publicDER, err := x509.MarshalPKIXPublicKey(fixture.ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(fixture.directory, "delegated-ledger.pub")
	writeFixture(t, publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
	outputPath := filepath.Join(fixture.directory, "issued-ledger.json")
	now := time.Now().UTC()
	args := []string{"sign-ledger-delegation", "--deployment", fixture.manifest.DeploymentID,
		"--cell", string(fixture.manifest.Cell), "--environment", fixture.manifest.Environment,
		"--signer-public-key", publicPath, "--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath,
		"--issued-at", now.Add(-time.Minute).Format(time.RFC3339),
		"--expires-at", now.Add(time.Hour).Format(time.RFC3339), "--out", outputPath}
	for _, slot := range fixture.manifest.ControllerSlots {
		args = append(args, "--slot", slot)
	}
	return fixture, args, outputPath, now
}

func TestSigningReportsCommandOutputFailure(t *testing.T) {
	failed := errors.New("status destination failed")
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "failed writer", err: failed, want: failed},
		{name: "short writer", want: io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, args, outputPath, now := ledgerSigningCommand(t)
			if err := Run(t.Context(), args, failedBootstrapOutput{err: test.err}); !errors.Is(err, test.want) {
				t.Fatalf("signing error = %v, want output failure %v", err, test.want)
			}
			wire, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := trust.DecodeEnvelope(wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := trust.VerifyDelegationCurrent(envelope, fixture.roots, now, bootstrap.BootstrapAnchorTrustPolicy()); err != nil {
				t.Fatalf("output failure obscured an invalid signing operation: %v", err)
			}
		})
	}
}

func TestCanceledSigningDoesNotPublishArtifact(t *testing.T) {
	_, args, outputPath, now := ledgerSigningCommand(t)
	ctx, cancel := context.WithCancel(t.Context())
	c := command{ctx: ctx, output: io.Discard}
	cancel()
	// Exercise the command directly so Run's entry check cannot mask a missing
	// cancellation guard at the create-only publication boundary.
	if err := c.signLedgerDelegationAt(args[1:], now); !errors.Is(err, context.Canceled) {
		t.Fatalf("signing error = %v, want cancellation", err)
	}
	if _, err := os.Lstat(outputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled signing published an artifact: %v", err)
	}
}

func TestCanceledCustomerPublicationLeavesNoPrivateTemporaryFile(t *testing.T) {
	directory := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	c := command{ctx: ctx, output: io.Discard}
	cancel()
	if err := c.writeNewCustomerMaterial(filepath.Join(directory, "customer.json"), []byte(`{"token":"secret"}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("customer publication error = %v, want cancellation", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("canceled customer publication created private files: entries=%v, error=%v", entries, err)
	}
}
