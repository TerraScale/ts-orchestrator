package attempt

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func smallAttempt(t *testing.T) *Attempt {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	wire := []byte(`{"workdir":"` + filepath.Join(dir, "work") + `","deployment_id":"0000000000F9PR1WNVDTEXS31Z","prefix":"bootstrap/a","tools":{}}`)
	if err := os.WriteFile(config, wire, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := New(t.Context(), config, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestRootMaterialCleanupRunsAfterCancellationAndFailure(t *testing.T) {
	a := smallAttempt(t)
	ctx, cancel := context.WithCancel(t.Context())
	a.ctx = ctx
	sentinel := errors.New("copy failed")
	cleaned := false
	a.Runner = func(ctx context.Context, c Command) (string, error) {
		switch {
		case slices.Contains(c.Args, "mktemp"):
			return "/run/material-copy\n", nil
		case slices.Contains(c.Args, "cp"):
			cancel()
			return "", sentinel
		case slices.Contains(c.Args, "rm"):
			if ctx.Err() != nil {
				t.Fatal("cleanup reused canceled attempt context")
			}
			if !slices.Contains(c.Args, "/run/material-copy") {
				t.Fatal(c.Args)
			}
			cleaned = true
			return "", nil
		}
		t.Fatal(c.Args)
		return "", nil
	}
	a.rootMaterial(func(string) { t.Fatal("used material after failed copy") })
	if !cleaned || !errors.Is(a.Err(), sentinel) {
		t.Fatal(cleaned, a.Err())
	}
}
