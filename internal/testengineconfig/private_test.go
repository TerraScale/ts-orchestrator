package testengineconfig

import (
	"os"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

func TestPrepareCreatesLoadableSixGuestFixture(t *testing.T) {
	f, err := Prepare(strings.Repeat("a", 64), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Remove() })
	if len(f.Bindings) != 6 || len(f.Declaration.Hosts) != 6 {
		t.Fatalf("fixture has %d bindings and %d hosts, want six", len(f.Bindings), len(f.Declaration.Hosts))
	}
	if info, err := os.Stat(f.Root); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("private root mode = %v, err = %v", info, err)
	}
	if _, err := vmengineconfig.Load(f.DeclarationPath, f.Declaration.ArtifactSHA256, f.Declaration.Release, f.Bindings); err != nil {
		t.Fatalf("prepared declaration failed Load: %v", err)
	}
}
