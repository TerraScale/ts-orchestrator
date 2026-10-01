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
)

func TestLocalCommandDispatchWithoutRuntimeConfig(t *testing.T) {
	for _, test := range []struct {
		args      []string
		want      string
		wantError bool
	}{
		{args: []string{"--help"}, want: "Usage: ts-orch"},
		{args: []string{"bootstrap", "--help"}, want: "sign-anchor"},
		{args: []string{"release", "--help"}, want: "sign-binary"},
		{args: []string{"image", "--help"}, want: "build-offline"},
		{args: []string{"netbird", "--help"}, want: "install"},
		{args: []string{"oci-region", "--help"}, want: "preview"},
		{args: []string{"qualification", "--help"}, want: "firecracker"},
		{args: []string{"qualification", "firecracker", "--help"}, want: "prepare-base"},
		{args: []string{"runtime-priority", "--help"}, want: "probe-admission"},
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
	for _, args := range [][]string{{"--help"}, {"bootstrap", "--help"}, {"release", "--help"}, {"image", "--help"}, {"netbird", "--help"}, {"oci-region", "--help"}, {"qualification", "--help"}, {"runtime-priority", "--help"}} {
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
