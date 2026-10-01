package cli

import (
	"bytes"
	"context"
	"errors"
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
