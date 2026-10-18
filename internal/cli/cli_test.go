package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestLocalCommandDispatchWithoutRuntimeConfig(t *testing.T) {
	t.Setenv("TS_VERIFY_LIVE", "")
	for _, test := range []struct {
		args      []string
		want      string
		wantError bool
	}{
		{args: []string{"--help"}, want: "Usage: ts-orch"},
		{args: []string{"verify", "--help"}, want: "opt in"},
		{args: []string{"verify"}, want: "requires --live", wantError: true},
		{args: []string{"log-scan", "--help"}, want: "--fly-app"},
		{args: []string{"dashboard", "--help"}, want: "three observed controllers"},
		{args: []string{"dashboard", "check"}, want: "requires --gru-token-file", wantError: true},
		{args: []string{"cost"}, want: "Usage: ts-orch cost report"},
		{args: []string{"cost", "report"}, want: "needs --region", wantError: true},
		{args: []string{"network", "--help"}, want: "--all"},
		{args: []string{"network", "check", "unexpected"}, want: "no positional arguments", wantError: true},
		{args: []string{"bootstrap", "--help"}, want: "sign-anchor"},
		{args: []string{"release", "--help"}, want: "sign-binary"},
		{args: []string{"image", "--help"}, want: "build-offline"},
		{args: []string{"netbird", "--help"}, want: "install"},
		{args: []string{"netbird", "path-audit", "--help"}, want: "--expected-ip"},
		{args: []string{"netbird", "path-audit"}, want: "requires --vault-id", wantError: true},
		{args: []string{"netbird", "sync", "--help"}, want: "prune-peers"},
		{args: []string{"netbird", "inventory", "unexpected"}, want: "no positional arguments", wantError: true},
		{args: []string{"oci-region", "--help"}, want: "preview"},
		{args: []string{"region", "--help"}, want: "create  BUNDLE"},
		{args: []string{"region", "create"}, want: "usage: ts-orch region create BUNDLE", wantError: true},
		{args: []string{"region", "plan"}, want: "needs a region argument", wantError: true},
		{args: []string{"region", "unknown", "fra"}, want: `unknown region command "unknown"`, wantError: true},
		{args: []string{"oci-region", "import-image", "--help"}, want: `unknown oci-region command "import-image"`, wantError: true},
		{args: []string{"oci-region", "import-image", "--qcow2", "candidate.qcow2", "--sha256", strings.Repeat("a", 64)}, want: `unknown oci-region command "import-image"`, wantError: true},
		{args: []string{"qualification", "--help"}, want: "firecracker"},
		{args: []string{"qualification", "firecracker", "--help"}, want: "prepare-base"},
		{args: []string{"runtime-priority", "--help"}, want: "probe-admission"},
		{args: []string{"ouroboros", "--help"}, want: "fly-secrets"},
		{args: []string{"vault", "--help"}, want: "render"},
		{args: []string{"disaster-recovery", "--help"}, want: "does not rebuild"},
		{args: []string{"disaster-recovery", "replicate"}, want: "requires --config", wantError: true},
		{args: []string{"disaster-recovery", "drill"}, want: "unknown disaster-recovery command", wantError: true},
		{args: []string{"vault", "put"}, want: "put requires", wantError: true},
		{args: []string{"ouroboros", "fly-secrets"}, want: "fly-secrets requires", wantError: true},
		{args: []string{"bootstrap", "verify-anchor"}, want: "verify-anchor requires", wantError: true},
		{args: []string{"release", "publish"}, want: "publish requires", wantError: true},
		{args: []string{"misspelled"}, want: "unknown command", wantError: true},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			var output bytes.Buffer
			err := Run(t.Context(), test.args, &output)
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("error = %v, want %q", err, test.want)
				}
				if output.Len() != 0 {
					t.Fatalf("failed command wrote data: %q", output.String())
				}
			} else if err != nil || !strings.Contains(output.String(), test.want) {
				t.Fatalf("output = %q, error = %v", output.String(), err)
			}
		})
	}
}

func TestCanceledCommandDoesNotCreateIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	key := filepath.Join(t.TempDir(), "identity.key")
	var output bytes.Buffer
	if err := Run(ctx, []string{"identity-new", "--key", key}, &output); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
	if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled command created a key: %v", err)
	}
}

type brokenOutput struct{ err error }

func (output brokenOutput) Write([]byte) (int, error) { return 0, output.err }

func TestHelpPropagatesOutputFailure(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"bootstrap", "--help"}, {"release", "--help"}, {"image", "--help"}, {"netbird", "--help"}, {"oci-region", "--help"}, {"qualification", "--help"}, {"runtime-priority", "--help"}, {"disaster-recovery", "--help"}} {
		for _, cause := range []error{io.ErrClosedPipe, nil} {
			want := cause
			if want == nil {
				want = io.ErrShortWrite
			}
			if err := Run(t.Context(), args, brokenOutput{err: cause}); !errors.Is(err, want) {
				t.Fatalf("%v error = %v, want %v", args, err, want)
			}
		}
	}
}

func TestRegionCreateRejectsUntrustedBundleBeforeOperator(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, test := range []struct {
		name string
		wire string
		want error
	}{
		{name: "malformed", wire: "{"},
		{name: "unknown member", wire: `{"unknown":true}`},
		{name: "unsigned", wire: "{}"},
		{name: "forged documents", wire: `{"tenancyId":"ocid1.tenancy.oc1..untrusted","namespace":"untrusted","rootChainWire":"e30=","anchorWire":"e30=","grantWire":"e30="}`, want: trust.ErrInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(path, []byte(test.wire), 0600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err := Run(t.Context(), []string{"region", "create", path}, &output)
			if err == nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want bundle refusal %v", err, test.want)
			}
			if output.Len() != 0 {
				t.Fatalf("rejected bundle wrote success output: %q", output.String())
			}
			wire, err := os.ReadFile(path)
			if err != nil || string(wire) != test.wire {
				t.Fatalf("bundle changed: %q, error = %v", wire, err)
			}
		})
	}
	for _, name := range []string{"directory", "oversized"} {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir()
			if name == "oversized" {
				path = filepath.Join(path, "bundle.json")
				file, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Truncate((3 << 20) + 1); err != nil {
					file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var output bytes.Buffer
			err := Run(t.Context(), []string{"region", "create", path}, &output)
			if err == nil || !strings.Contains(err.Error(), "foundation bundle must be a bounded regular file") || output.Len() != 0 {
				t.Fatalf("output = %q, error = %v, want bounded regular file refusal", output.String(), err)
			}
		})
	}
}
