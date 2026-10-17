package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestFoundationCeremonyCLIRejectsUnsafeFilesWithoutOutput(t *testing.T) {
	fixture := newManifestFixture(t, time.Hour, time.Hour)
	prepared, err := trust.EncodePayload(region.FoundationPreparation{})
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(fixture.directory, "foundation.json")
	chainPath := filepath.Join(fixture.directory, "root-chain.json")
	chain, err := trust.EncodeRootChain(trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, candidate, prepared, 0o644)
	writeFixture(t, chainPath, chain, 0o644)
	output := filepath.Join(fixture.directory, "signed-foundation.json")
	args := []string{"sign-foundation", "--candidate", candidate, "--root-chain", chainPath, "--root-key", fixture.rootPath, "--signing-key", fixture.privatePath, "--out", output}
	for _, scenario := range []struct {
		name string
		edit func()
	}{
		{name: "unknown approval field", edit: func() { writeFixture(t, candidate, []byte(`{"grant":{},"anchor":{},"unexpected":true}`), 0o644) }},
		{name: "candidate symlink", edit: func() {
			if err := os.Remove(candidate); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(chainPath, candidate); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "root key permissions", edit: func() {
			if err := os.Remove(candidate); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, candidate, prepared, 0o644)
			if err := os.Chmod(fixture.privatePath, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			scenario.edit()
			if err := Run(t.Context(), args, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe or incomplete ceremony input was signed")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected ceremony created output: %v", err)
			}
		})
	}
}

func TestFoundationPublicationCLIRejectsInputBeforeOCI(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "bundle.json")
	if err := os.WriteFile(path, []byte(`{"tenancyId":"ocid1.tenancy.oc1..test","unknown":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Run(t.Context(), []string{"publish-foundation", "--bundle", path}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("malformed bundle did not fail before OCI client construction: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := Run(ctx, []string{"publish-foundation", "--bundle", path}, &bytes.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled publication: %v", err)
	}
}

func TestFoundationProvisionCLIRejectsInputBeforeOCI(t *testing.T) {
	directory := t.TempDir()
	malformed := filepath.Join(directory, "malformed.json")
	invalid := filepath.Join(directory, "invalid.json")
	oversized := filepath.Join(directory, "oversized.json")
	link := filepath.Join(directory, "symlink.json")
	writeFixture(t, malformed, []byte(`{"unknown":true}`), 0o644)
	writeFixture(t, invalid, []byte(`{}`), 0o644)
	writeFixture(t, oversized, bytes.Repeat([]byte(" "), maxFoundationBundleBytes+1), 0o644)
	if err := os.Symlink(invalid, link); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name string
		args []string
		want string
	}{
		{name: "missing bundle", args: []string{"foundation", "provision"}, want: "exactly one signed BUNDLE"},
		{name: "extra argument", args: []string{"foundation", "provision", invalid, "extra"}, want: "exactly one signed BUNDLE"},
		{name: "unknown field", args: []string{"foundation", "provision", malformed}, want: "unknown"},
		{name: "invalid authority", args: []string{"foundation", "provision", invalid}, want: "retained foundation has invalid locators or document bounds"},
		{name: "symlink", args: []string{"foundation", "provision", link}, want: "must be a regular file"},
		{name: "oversized", args: []string{"foundation", "provision", oversized}, want: "exceeds the"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := Run(t.Context(), scenario.args, &output); err == nil || !strings.Contains(err.Error(), scenario.want) {
				t.Fatalf("input did not fail before OCI credential loading: %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("rejected provisioning wrote output: %q", output.String())
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := Run(ctx, []string{"foundation", "provision", invalid}, &bytes.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled provisioning: %v", err)
	}
}
