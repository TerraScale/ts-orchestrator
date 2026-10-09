package attempt

import (
	"bytes"
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
func TestResumePreservesHistoricalJSONBytes(t *testing.T) {
	a := smallAttempt(t)
	path := a.Path("retained.json")
	retained := []byte("{\n \"identity\": \"signed-before-migration\",\n \"generation\": 1\n}\n")
	if err := os.WriteFile(path, retained, 0600); err != nil {
		t.Fatal(err)
	}
	a.writeJSON(path, Object{"identity": "signed-before-migration", "generation": 1})
	got, err := os.ReadFile(path)
	if err != nil || a.Err() != nil || !bytes.Equal(got, retained) {
		t.Fatal(string(got), err, a.Err())
	}
	a.writeJSON(path, Object{"identity": "changed", "generation": 1})
	if a.Err() == nil {
		t.Fatal("accepted immutable record identity change")
	}
	got, _ = os.ReadFile(path)
	if !bytes.Equal(got, retained) {
		t.Fatal("changed retained signed bytes")
	}
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
