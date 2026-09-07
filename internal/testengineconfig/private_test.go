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
	destination := f.Declaration.Databases[0].Backup.Destinations[0]
	if destination.Provider != "tigris" || destination.Endpoint != "https://fly.storage.tigris.dev" || destination.VerifiedGeography != "BR" || len(destination.PermittedGeographies) != 1 || destination.PermittedGeographies[0] != "BR" {
		t.Fatalf("backup destination is not the approved qualification target: %+v", destination)
	}
	for _, path := range []string{destination.AccessKeyFile, destination.SecretKeyFile} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 || info.Size() == 0 {
			t.Fatalf("backup credential %q is not a private nonempty file: %v", path, err)
		}
	}
	wantGateway := map[string]string{"GRU": "10.77.0.1", "SFO": "10.77.1.1", "FRA": "10.77.2.1"}
	for _, host := range f.Declaration.Hosts {
		want := "tls://" + wantGateway[hostRegion(f.Bindings, host.NodeID)] + ":4222"
		if host.EngineControl.NATSURL != want || host.DatabaseHost.NATSURL != want {
			t.Errorf("%s NATS URLs = %q and %q, want %q", host.NodeID, host.EngineControl.NATSURL, host.DatabaseHost.NATSURL, want)
		}
	}
}

func hostRegion(bindings []vmengineconfig.Binding, nodeID string) string {
	for _, binding := range bindings {
		if binding.NodeID == nodeID {
			return binding.Region
		}
	}
	return ""
}
